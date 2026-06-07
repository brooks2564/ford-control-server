"""
Ford Control Server — Flask middleware for Pebble Ford Control watchapp.
Uses Ford OAuth 2.0 + PKCE for auth, then Autonomic API for vehicle commands.
Ford decommissioned usapi.cv.ford.com — all vehicle calls now go to api.autonomic.ai.
"""

import os, time, hashlib, base64, urllib.parse, requests, json
from flask import Flask, jsonify, request, redirect, render_template_string

app = Flask(__name__)

FORD_VIN               = os.environ.get('FORD_VIN', '').upper()
API_KEY                = os.environ.get('FORD_API_KEY', 'changeme')
FORD_REFRESH_TOKEN_ENV = os.environ.get('FORD_REFRESH_TOKEN', '')
FORD_EMAIL             = os.environ.get('FORD_EMAIL', '')
FORD_PASSWORD          = os.environ.get('FORD_PASSWORD', '')
UPSTASH_URL            = os.environ.get('UPSTASH_REDIS_URL', 'https://mint-dodo-83959.upstash.io').rstrip('/')
UPSTASH_TOKEN          = os.environ.get('UPSTASH_REDIS_TOKEN', 'gQAAAAAAAUf3AAIgcDI1MjliYTBhZjU3NGM0MjI5OTczYzA4YTgyN2ZhYmRjZQ')

# ── Ford OAuth constants ──────────────────────────────────────────────────────
OAUTH_ID   = '4566605f-43a7-400a-946e-89cc9fdb0bd7'
CLIENT_ID  = '09852200-05fd-41f6-8c21-d36d3497dc64'
APP_ID     = '71A3AD0A-CF46-4CCF-B473-FC7FE5BC4592'
LOCALE     = 'en-US'
REDIRECT   = 'fordapp://userauthorized'
LOGIN_BASE = f'https://login.ford.com/{OAUTH_ID}/B2C_1A_SignInSignUp_{LOCALE}/oauth2/v2.0'
ROPC_BASE  = f'https://login.ford.com/{OAUTH_ID}/B2C_1A_ROPC_Auth/oauth2/v2.0'
B2C_URL    = 'https://api.foundational.ford.com/api/token/v2/cat-with-b2c-access-token'
REFRESH_URL = 'https://api.foundational.ford.com/api/token/v2/cat-with-refresh-token'

# ── Autonomic API constants ───────────────────────────────────────────────────
AUTO_TOKEN_URL  = 'https://accounts.autonomic.ai/v1/auth/oidc/token'
AUTO_API        = 'https://api.autonomic.ai/v1'
AUTO_CMD_URL    = f'{AUTO_API}/command/vehicles/{FORD_VIN}/commands'
AUTO_STATUS_URL = f'{AUTO_API}/telemetry/sources/fordpass/vehicles/{FORD_VIN}'

COMMON_HEADERS = {
    'Accept-Encoding': 'gzip',
    'Connection': 'keep-alive',
    'User-Agent': 'okhttp/4.12.0',
}

# ── Token store ───────────────────────────────────────────────────────────────
_ford = {
    'access_token':  None,
    'refresh_token': FORD_REFRESH_TOKEN_ENV or None,
    'expires_at':    0,
    'code_verifier': None,
}

_auto = {
    'access_token': None,
    'expires_at':   0,
}
_last_callback = {}  # debug: last request to /auth/callback

# ── PKCE helpers ──────────────────────────────────────────────────────────────
def _make_verifier():
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode()

def _make_challenge(v):
    return base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()

# ── Upstash Redis persistence ─────────────────────────────────────────────────
def _upstash_save(token):
    if not UPSTASH_URL or not UPSTASH_TOKEN:
        return
    try:
        requests.post(f'{UPSTASH_URL}/set/ford_refresh_token',
                      headers={'Authorization': f'Bearer {UPSTASH_TOKEN}',
                               'Content-Type': 'application/json'},
                      json=token, timeout=5)
    except Exception:
        pass

def _upstash_load():
    if not UPSTASH_URL or not UPSTASH_TOKEN:
        return None
    try:
        r = requests.get(f'{UPSTASH_URL}/get/ford_refresh_token',
                         headers={'Authorization': f'Bearer {UPSTASH_TOKEN}'},
                         timeout=5)
        val = r.json().get('result')
        return val.strip('"') if isinstance(val, str) else val
    except Exception:
        return None

# Load latest token from Upstash on startup (overrides env var with most recent rotated token)
_persisted = _upstash_load()
if _persisted:
    _ford['refresh_token'] = _persisted

# ── Ford token management ─────────────────────────────────────────────────────
def _login_with_password(email, password):
    """ROPC grant — exchanges FordPass credentials for tokens, no browser needed."""
    r = requests.post(f'{ROPC_BASE}/token',
                      headers={**COMMON_HEADERS, 'Content-Type': 'application/x-www-form-urlencoded'},
                      data={
                          'grant_type':  'password',
                          'username':    email,
                          'password':    password,
                          'client_id':   CLIENT_ID,
                          'scope':       f'openid {CLIENT_ID}',
                          'response_type': 'token',
                      }, timeout=15)
    r.raise_for_status()
    b2c_token = r.json().get('access_token')
    if not b2c_token:
        raise RuntimeError(f'ROPC: no access_token — {r.text[:200]}')
    r2 = requests.post(B2C_URL,
                       headers={**COMMON_HEADERS, 'Content-Type': 'application/json',
                                 'Application-Id': APP_ID},
                       json={'idpToken': b2c_token}, timeout=15)
    r2.raise_for_status()
    data = r2.json()
    _ford['access_token']  = data['access_token']
    _ford['refresh_token'] = data.get('refresh_token')
    _ford['expires_at']    = time.time() + int(data.get('expires_in', 1800)) - 60
    _auto['access_token']  = None

def _refresh_ford_token():
    r = requests.post(REFRESH_URL,
                      headers={**COMMON_HEADERS, 'Content-Type': 'application/json',
                                'Application-Id': APP_ID},
                      json={'refresh_token': _ford['refresh_token']}, timeout=15)
    r.raise_for_status()
    data = r.json()
    _ford['access_token'] = data['access_token']
    _ford['expires_at']   = time.time() + int(data.get('expires_in', 1800)) - 60
    if data.get('refresh_token'):
        _ford['refresh_token'] = data['refresh_token']
        _upstash_save(_ford['refresh_token'])
    _auto['access_token'] = None  # invalidate autonomic token

def get_ford_token():
    if not _ford['refresh_token'] and not _ford['access_token']:
        raise RuntimeError('Not authenticated — visit /auth to log in')
    if not _ford['access_token'] or time.time() >= _ford['expires_at']:
        _refresh_ford_token()
    return _ford['access_token']

# ── Autonomic token management ────────────────────────────────────────────────
def get_auto_token():
    if _auto['access_token'] and time.time() < _auto['expires_at']:
        return _auto['access_token']
    ford_token = get_ford_token()
    r = requests.post(AUTO_TOKEN_URL,
                      headers={'Accept': '*/*',
                               'Content-Type': 'application/x-www-form-urlencoded'},
                      data={
                          'subject_token':      ford_token,
                          'subject_issuer':     'fordpass',
                          'client_id':          'fordpass-prod',
                          'grant_type':         'urn:ietf:params:oauth:grant-type:token-exchange',
                          'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',
                      }, timeout=15)
    r.raise_for_status()
    data = r.json()
    _auto['access_token'] = data['access_token']
    _auto['expires_at']   = time.time() + int(data.get('expires_in', 1800)) - 60
    return _auto['access_token']

def auto_headers():
    return {'Authorization': f'Bearer {get_auto_token()}',
            'Content-Type': 'application/json',
            **COMMON_HEADERS}

# ── Auth guard ────────────────────────────────────────────────────────────────
def require_api_key(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get('X-API-Key') != API_KEY:
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# ── Vehicle data helpers ──────────────────────────────────────────────────────
def get_vehicle_status():
    r = requests.get(AUTO_STATUS_URL, headers=auto_headers(), timeout=15)
    r.raise_for_status()
    return r.json()

def parse_status(data):
    metrics = data.get('metrics', {})
    states  = data.get('states',  {})

    def metric_val(key):
        m = metrics.get(key, {})
        return m.get('value') if isinstance(m, dict) else None

    def state_val(key):
        s = states.get(key, {})
        return s.get('value') if isinstance(s, dict) else None

    locked_raw  = metric_val('doorLockStatus') or state_val('lockStatus') or 'LOCKED'
    engine_raw  = metric_val('ignitionStatus') or state_val('ignitionStatus') or 'Off'
    locked      = str(locked_raw).upper() in ('LOCKED', 'LOCK', '1', 'TRUE')
    running     = str(engine_raw).lower() not in ('off', 'offrun', '0', 'false')

    return {'is_locked': locked, 'is_running': running, 'model_name': 'Maverick'}

def parse_info(data):
    metrics = data.get('metrics', {})

    def mv(key):
        m = metrics.get(key, {})
        v = m.get('value') if isinstance(m, dict) else None
        try: return float(v)
        except: return None

    def psi(kpa):
        try: return int(float(kpa) * 0.145038)
        except: return -1

    fuel = mv('fuelLevel') or mv('batteryStateOfCharge')
    oil  = mv('oilLifeRemaining') or mv('engineOilLife')
    fl   = mv('tirePressureFL') or mv('leftFrontTirePressure')
    fr   = mv('tirePressureFR') or mv('rightFrontTirePressure')
    rl   = mv('tirePressureRL') or mv('leftRearTirePressure')
    rr   = mv('tirePressureRR') or mv('rightRearTirePressure')

    return {
        'fuel_level': int(fuel) if fuel is not None else -1,
        'oil_life':   int(oil)  if oil  is not None else -1,
        'tire_fl': psi(fl) if fl else -1,
        'tire_fr': psi(fr) if fr else -1,
        'tire_rl': psi(rl) if rl else -1,
        'tire_rr': psi(rr) if rr else -1,
    }

def send_command(cmd_type, properties=None):
    body = {'type': cmd_type, 'wakeUp': True, 'tags': {}}
    if properties:
        body['properties'] = properties
    r = requests.post(AUTO_CMD_URL, headers=auto_headers(), json=body, timeout=20)
    r.raise_for_status()
    return r.json()

# ── Auth HTML ─────────────────────────────────────────────────────────────────
AUTH_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Ford Control — Setup</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px;
           background: #f5f5f5; color: #333; }
    h1 { color: #003087; }
    .step { background: white; border-radius: 8px; padding: 20px; margin: 16px 0;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1); }
    .step h2 { margin-top: 0; font-size: 1rem; color: #003087; }
    a.btn { display: inline-block; background: #003087; color: white;
            padding: 12px 24px; border-radius: 6px; text-decoration: none;
            font-weight: bold; margin: 8px 0; }
    input[type=text] { width: 100%; padding: 10px; font-size: 0.9rem;
                        border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    button { background: #003087; color: white; border: none; padding: 12px 24px;
             border-radius: 6px; font-size: 1rem; cursor: pointer; margin-top: 8px; }
    .status { padding: 10px 16px; border-radius: 6px; margin: 8px 0; }
    .ok  { background: #d4edda; color: #155724; }
    .err { background: #f8d7da; color: #721c24; }
    code { background: #eee; padding: 2px 6px; border-radius: 3px; font-size: 0.85rem;
           word-break: break-all; }
  </style>
</head>
<body>
  <h1>🚙 Ford Control — One-Time Setup</h1>
  {% if authenticated %}
    <div class="status ok">✅ Authenticated! Your Pebble app is ready to use.</div>
  {% else %}
    <div class="status err">⚠️ Not authenticated yet. Follow the steps below.</div>
  {% endif %}

  <div class="step">
    <h2>Step 1 — Open Ford login in Chrome with DevTools open</h2>
    <p>Click below. Before logging in, open DevTools (F12) → Network tab → check <strong>Preserve log</strong>.</p>
    <a class="btn" href="{{ auth_url }}" target="_blank">Log in with Ford →</a>
  </div>

  <div class="step">
    <h2>Step 2 — Copy the fordapp:// URL</h2>
    <p>After logging in, find the <strong>userauthorized</strong> entry in the Network tab.
       Click it and copy the full Request URL starting with <code>fordapp://userauthorized/?code=</code></p>
  </div>

  <div class="step">
    <h2>Step 3 — Paste it here</h2>
    <form action="/auth/complete" method="POST">
      <input type="text" name="redirect_url"
             placeholder="fordapp://userauthorized/?code=..." required>
      <br>
      <button type="submit">Complete Setup</button>
    </form>
  </div>

  {% if message %}
    <div class="status {{ 'ok' if success else 'err' }}">{{ message }}</div>
  {% endif %}
</body>
</html>
"""

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route('/auth')
def auth_page():
    verifier  = _make_verifier()
    challenge = _make_challenge(verifier)
    _ford['code_verifier'] = verifier
    params = {
        'redirect_uri': REDIRECT, 'response_type': 'code', 'max_age': '3600',
        'code_challenge': challenge, 'code_challenge_method': 'S256',
        'scope': f'{CLIENT_ID} openid', 'client_id': CLIENT_ID,
        'ui_locales': LOCALE, 'language_code': LOCALE,
        'ford_application_id': APP_ID, 'country_code': 'USA',
    }
    auth_url = f'{LOGIN_BASE}/authorize?' + urllib.parse.urlencode(params)
    return render_template_string(AUTH_PAGE, auth_url=auth_url,
                                  authenticated=bool(_ford['access_token']),
                                  message=None, success=False)

@app.route('/auth/start')
def auth_start():
    verifier  = _make_verifier()
    challenge = _make_challenge(verifier)
    _ford['code_verifier'] = verifier
    params = {
        'redirect_uri': REDIRECT, 'response_type': 'code', 'max_age': '3600',
        'code_challenge': challenge, 'code_challenge_method': 'S256',
        'scope': f'{CLIENT_ID} openid', 'client_id': CLIENT_ID,
        'ui_locales': LOCALE, 'language_code': LOCALE,
        'ford_application_id': APP_ID, 'country_code': 'USA',
    }
    ford_url = f'{LOGIN_BASE}/authorize?' + urllib.parse.urlencode(params)
    return f'''<!DOCTYPE html>
<html>
<head><title>Ford Login</title>
<style>
  body {{ font-family: sans-serif; display: flex; flex-direction: column;
          align-items: center; justify-content: center; height: 100vh;
          margin: 0; background: #003087; color: white; }}
  h2 {{ margin-bottom: 8px; }}
  p  {{ margin-bottom: 32px; opacity: 0.8; text-align: center; }}
  a  {{ background: white; color: #003087; padding: 16px 40px; border-radius: 8px;
        text-decoration: none; font-weight: bold; font-size: 1.1rem; }}
</style>
</head>
<body>
  <h2>Ford Control Setup</h2>
  <p>Make sure DevTools is open (F12) and Network tab has<br>
     <strong>Preserve log</strong> checked before clicking.</p>
  <a href="{ford_url}">Sign in with Ford &rarr;</a>
</body>
</html>'''

@app.route('/auth/callback')
def auth_callback():
    _last_callback.update({'args': dict(request.args), 'time': time.time()})
    """Ford redirects here after login (server-side redirect_uri flow)."""
    code  = request.args.get('code', '').strip()
    error = request.args.get('error', '')
    if error:
        return f'<h2>Ford error: {error}</h2><p>{request.args.get("error_description","")}</p>', 400
    if not code:
        return '<h2>No code returned by Ford.</h2>', 400
    verifier = _ford.get('code_verifier')
    if not verifier:
        return '<h2>Session expired. <a href="/auth/server">Try again</a>.</h2>', 400
    try:
        r = requests.post(f'{LOGIN_BASE}/token',
                          headers={**COMMON_HEADERS, 'Content-Type': 'application/x-www-form-urlencoded'},
                          data={'client_id': CLIENT_ID, 'scope': f'{CLIENT_ID} openid',
                                'redirect_uri': request.url_root.rstrip('/') + '/auth/callback',
                                'grant_type': 'authorization_code',
                                'code': code, 'code_verifier': verifier}, timeout=15)
        r.raise_for_status()
        b2c_token = r.json()['access_token']
        r2 = requests.post(B2C_URL,
                           headers={**COMMON_HEADERS, 'Content-Type': 'application/json',
                                     'Application-Id': APP_ID},
                           json={'idpToken': b2c_token}, timeout=15)
        r2.raise_for_status()
        data = r2.json()
        _ford['access_token']  = data['access_token']
        _ford['refresh_token'] = data.get('refresh_token')
        _ford['expires_at']    = time.time() + int(data.get('expires_in', 1800)) - 60
        _ford['code_verifier'] = None
        _auto['access_token']  = None
        rt = _ford['refresh_token'] or ''
        return f'''<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;padding:20px">
<h2 style="color:green">&#10003; Authentication successful!</h2>
<p>Your Pebble app is ready to use.</p>
<p><strong>Save this refresh token as FORD_REFRESH_TOKEN in Render so auth survives restarts:</strong></p>
<textarea rows="4" style="width:100%;font-size:0.8rem">{rt}</textarea>
</body></html>'''
    except Exception as e:
        return f'<h2>Auth failed: {e}</h2>', 502

@app.route('/auth/server')
def auth_server():
    """Auth flow using our server URL as redirect_uri — no fordapp:// needed."""
    verifier  = _make_verifier()
    challenge = _make_challenge(verifier)
    _ford['code_verifier'] = verifier
    callback  = request.url_root.rstrip('/') + '/auth/callback'
    params = {
        'redirect_uri': callback, 'response_type': 'code', 'max_age': '3600',
        'code_challenge': challenge, 'code_challenge_method': 'S256',
        'scope': f'{CLIENT_ID} openid', 'client_id': CLIENT_ID,
        'ui_locales': LOCALE, 'language_code': LOCALE,
        'ford_application_id': APP_ID, 'country_code': 'USA',
    }
    return redirect(f'{LOGIN_BASE}/authorize?' + urllib.parse.urlencode(params))

@app.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    """Password login — uses FORD_EMAIL + FORD_PASSWORD env vars (or POST body)."""
    if request.method == 'GET':
        email = FORD_EMAIL
        pwd   = FORD_PASSWORD
    else:
        data  = request.get_json() or request.form
        email = data.get('email')    or FORD_EMAIL
        pwd   = data.get('password') or FORD_PASSWORD
    if not email or not pwd:
        return jsonify({'error': 'Set FORD_EMAIL and FORD_PASSWORD env vars on Render, or POST {email, password}'}), 400
    try:
        _login_with_password(email, pwd)
        return jsonify({'ok': True, 'message': 'Logged in! Save this refresh token to FORD_REFRESH_TOKEN on Render.',
                        'refresh_token': _ford.get('refresh_token', '')})
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/auth/complete', methods=['POST'])
def auth_complete():
    redirect_url = request.form.get('redirect_url', '').strip()
    verifier     = _ford.get('code_verifier')
    if not verifier:
        return render_template_string(AUTH_PAGE, auth_url='', authenticated=False,
                                      message='Session expired — go back to /auth and start again.',
                                      success=False)
    try:
        parsed = urllib.parse.urlparse(redirect_url)
        code   = urllib.parse.parse_qs(parsed.query).get('code', [None])[0]
        if not code:
            raise ValueError('No code')
    except Exception:
        return render_template_string(AUTH_PAGE, auth_url='', authenticated=False,
                                      message='Could not find code in that URL.',
                                      success=False)
    try:
        r = requests.post(f'{LOGIN_BASE}/token',
                          headers={**COMMON_HEADERS,
                                   'Content-Type': 'application/x-www-form-urlencoded'},
                          data={'client_id': CLIENT_ID, 'scope': f'{CLIENT_ID} openid',
                                'redirect_uri': REDIRECT, 'grant_type': 'authorization_code',
                                'code': code, 'code_verifier': verifier}, timeout=15)
        r.raise_for_status()
        b2c_token = r.json()['access_token']

        r2 = requests.post(B2C_URL,
                           headers={**COMMON_HEADERS, 'Content-Type': 'application/json',
                                     'Application-Id': APP_ID},
                           json={'idpToken': b2c_token}, timeout=15)
        r2.raise_for_status()
        data = r2.json()
        _ford['access_token']  = data['access_token']
        _ford['refresh_token'] = data['refresh_token']
        _ford['expires_at']    = time.time() + int(data.get('expires_in', 1800)) - 60
        _ford['code_verifier'] = None
        _auto['access_token']  = None
        _upstash_save(_ford['refresh_token'])

        rt = _ford.get('refresh_token', '')
        return render_template_string(AUTH_PAGE, auth_url='', authenticated=True,
                                      message=f'✅ Authentication successful! Save this refresh token to FORD_REFRESH_TOKEN in Render: {rt}',
                                      success=True, refresh_token=rt)
    except Exception as e:
        return render_template_string(AUTH_PAGE, auth_url='', authenticated=False,
                                      message=f'Auth failed: {str(e)}', success=False)

# ── Health ────────────────────────────────────────────────────────────────────
@app.route('/health')
def health():
    return jsonify({'ok': True,
                    'authenticated': bool(_ford['access_token'] or _ford['refresh_token']),
                    'has_env_token': bool(FORD_REFRESH_TOKEN_ENV),
                    'has_mem_token': bool(_ford['refresh_token']),
                    'env_token_len': len(FORD_REFRESH_TOKEN_ENV),
                    'last_callback': _last_callback})

@app.route('/auth/refresh-token')
@require_api_key
def get_refresh_token():
    if not _ford['refresh_token']:
        return jsonify({'error': 'not authenticated'}), 403
    return jsonify({'refresh_token': _ford['refresh_token']})

# ── Vehicle routes ────────────────────────────────────────────────────────────
@app.route('/status')
@require_api_key
def status():
    try:
        data = get_vehicle_status()
        return jsonify(parse_status(data))
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/info')
@require_api_key
def info():
    try:
        data   = get_vehicle_status()
        result = parse_status(data)
        result.update(parse_info(data))
        return jsonify(result)
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/lock', methods=['POST'])
@require_api_key
def lock():
    try:
        send_command('lock')
        time.sleep(3)
        result = parse_status(get_vehicle_status())
        result['is_locked'] = True
        return jsonify(result)
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/unlock', methods=['POST'])
@require_api_key
def unlock():
    try:
        send_command('unlock')
        time.sleep(3)
        result = parse_status(get_vehicle_status())
        result['is_locked'] = False
        return jsonify(result)
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/start', methods=['POST'])
@require_api_key
def start():
    try:
        send_command('remoteStart')
        time.sleep(4)
        result = parse_status(get_vehicle_status())
        result['is_running'] = True
        return jsonify(result)
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/stop', methods=['POST'])
@require_api_key
def stop():
    try:
        send_command('cancelRemoteStart')
        time.sleep(3)
        result = parse_status(get_vehicle_status())
        result['is_running'] = False
        return jsonify(result)
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/find', methods=['POST'])
@require_api_key
def find():
    try:
        send_command('startPanicCue', {'duration': 5})
        return jsonify({'ok': True, 'is_locked': True, 'is_running': False,
                        'model_name': 'Maverick'})
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/climate', methods=['POST'])
@require_api_key
def climate():
    body    = request.get_json() or {}
    seat    = bool(body.get('seat',    False))
    wheel   = bool(body.get('wheel',   False))
    defrost = bool(body.get('defrost', False))
    temp    = int(body.get('temp',     72))
    try:
        hdrs = auto_headers()
        if seat or wheel or defrost:
            send_command('startOnDemandPreconditioning',
                         {'preconditioningDuration': 10,
                          'vehiclePreconditionSetting': 1})
        data   = get_vehicle_status()
        result = parse_status(data)
        result.update({'climate_temp': temp, 'climate_seat': seat,
                       'climate_wheel': wheel, 'climate_defrost': defrost})
        return jsonify(result)
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502

# Auto-login on startup if credentials available and no refresh token seeded from env
if FORD_EMAIL and FORD_PASSWORD and not FORD_REFRESH_TOKEN_ENV:
    try:
        _login_with_password(FORD_EMAIL, FORD_PASSWORD)
        print(f'Startup auto-login succeeded for {FORD_EMAIL}')
    except Exception as _e:
        print(f'Startup auto-login failed: {_e}')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
