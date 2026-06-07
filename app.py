"""
Ford Control Server — Flask middleware for Pebble Ford Control watchapp.
Uses Ford's current OAuth 2.0 + PKCE auth flow (as of 2025-2026).

One-time setup: visit /auth in a browser to authenticate with Ford.
After that, tokens auto-refresh until the server restarts.
"""

import os, time, hashlib, base64, json, secrets, urllib.parse
import requests
from flask import Flask, jsonify, request, redirect, render_template_string

app = Flask(__name__)

FORD_VIN              = os.environ.get('FORD_VIN', '').upper()
API_KEY               = os.environ.get('FORD_API_KEY', 'changeme')
FORD_REFRESH_TOKEN_ENV = os.environ.get('FORD_REFRESH_TOKEN', '')

# ── Ford OAuth constants ──────────────────────────────────────────────────────
OAUTH_ID    = '4566605f-43a7-400a-946e-89cc9fdb0bd7'
CLIENT_ID   = '09852200-05fd-41f6-8c21-d36d3497dc64'
APP_ID      = '71A3AD0A-CF46-4CCF-B473-FC7FE5BC4592'
LOCALE      = 'en-US'
COUNTRY     = 'USA'
REDIRECT    = 'fordapp://userauthorized'

LOGIN_BASE  = f'https://login.ford.com/{OAUTH_ID}/B2C_1A_SignInSignUp_{LOCALE}/oauth2/v2.0'
TOKEN_URL   = f'{LOGIN_BASE}/token'
B2C_TOKEN_URL  = 'https://api.foundational.ford.com/api/token/v2/cat-with-b2c-access-token'
REFRESH_URL    = 'https://api.foundational.ford.com/api/token/v2/cat-with-refresh-token'
API_BASE       = 'https://usapi.cv.ford.com/api'

COMMON_HEADERS = {
    'Accept-Encoding': 'gzip',
    'Connection': 'keep-alive',
    'User-Agent': 'okhttp/4.12.0',
}

# ── In-memory token store ─────────────────────────────────────────────────────
_auth = {
    'access_token':  None,
    'refresh_token': FORD_REFRESH_TOKEN_ENV or None,  # pre-seed from env var
    'expires_at':    0,
    'code_verifier': None,
}

# ── PKCE helpers ──────────────────────────────────────────────────────────────
def _make_verifier():
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode()

def _make_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

# ── Token management ──────────────────────────────────────────────────────────
def _refresh_access_token():
    r = requests.post(REFRESH_URL,
                      headers={**COMMON_HEADERS, 'Content-Type': 'application/json',
                                'Application-Id': APP_ID},
                      json={'refresh_token': _auth['refresh_token']},
                      timeout=15)
    r.raise_for_status()
    data = r.json()
    _auth['access_token'] = data['access_token']
    _auth['expires_at']   = time.time() + int(data.get('expires_in', 1800)) - 60
    if data.get('refresh_token'):
        _auth['refresh_token'] = data['refresh_token']

def get_access_token():
    if not _auth['access_token']:
        raise RuntimeError('Not authenticated — visit /auth to log in')
    if time.time() >= _auth['expires_at']:
        _refresh_access_token()
    return _auth['access_token']

def api_headers():
    return {
        **COMMON_HEADERS,
        'Application-Id': APP_ID,
        'auth-token': get_access_token(),
        'Content-Type': 'application/json',
    }

# ── Auth guard ────────────────────────────────────────────────────────────────
def require_api_key(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get('X-API-Key') != API_KEY:
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# ── Status parsing ────────────────────────────────────────────────────────────
def parse_status(vs):
    locked  = vs.get('lockStatus', {}).get('value', 'LOCKED').upper() == 'LOCKED'
    running = vs.get('ignitionStatus', {}).get('value', 'Off').lower() not in ('off', 'offrun')
    return {'is_locked': locked, 'is_running': running, 'model_name': 'Maverick'}

def parse_info(vs):
    def psi(kpa):
        try: return int(float(kpa) * 0.145038)
        except: return -1

    fuel = -1
    f = vs.get('fuel', {})
    if f: fuel = int(float(f.get('fuelLevel', -1)))

    oil = -1
    o = vs.get('oil', {})
    if o: oil = int(float(o.get('oilLifeActual', -1)))

    tpms = vs.get('TPMS', {})
    return {
        'fuel_level': fuel,
        'oil_life':   oil,
        'tire_fl': psi(tpms.get('leftFrontTirePressure',  {}).get('value', -1)),
        'tire_fr': psi(tpms.get('rightFrontTirePressure', {}).get('value', -1)),
        'tire_rl': psi(tpms.get('leftRearTirePressure',   {}).get('value', -1)),
        'tire_rr': psi(tpms.get('rightRearTirePressure',  {}).get('value', -1)),
    }

def get_vehicle_status():
    r = requests.get(
        f'{API_BASE}/vehicles/v4/{FORD_VIN}/status',
        params={'lrdt': '01-01-1970 00:00:00'},
        headers=api_headers(), timeout=15)
    r.raise_for_status()
    return r.json()['vehiclestatus']

def poll_command(url, command_id, retries=6):
    for _ in range(retries):
        r = requests.get(f'{url}/{command_id}', headers=api_headers(), timeout=15)
        result = r.json()
        if result.get('status') == 200:
            return True
        if result.get('status') != 552:
            return False
        time.sleep(5)
    return False

# ── Auth HTML page ────────────────────────────────────────────────────────────
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
    <h2>Step 1 — Open Ford login in a desktop browser</h2>
    <p>Click the button below. <strong>Use a desktop/laptop browser, not your phone.</strong>
       Log in with your FordPass email and password.</p>
    <a class="btn" href="{{ auth_url }}" target="_blank">Log in with Ford →</a>
  </div>

  <div class="step">
    <h2>Step 2 — Copy the redirect URL</h2>
    <p>After logging in, your browser will show an error like
       <em>"can't open fordapp://"</em> — that's expected.<br>
       Copy the <strong>full URL</strong> from your browser's address bar.
       It starts with <code>fordapp://userauthorized/?code=</code></p>
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
    verifier   = _make_verifier()
    challenge  = _make_challenge(verifier)
    _auth['code_verifier'] = verifier

    params = {
        'redirect_uri':         REDIRECT,
        'response_type':        'code',
        'max_age':              '3600',
        'code_challenge':       challenge,
        'code_challenge_method':'S256',
        'scope':                f'{CLIENT_ID} openid',
        'client_id':            CLIENT_ID,
        'ui_locales':           LOCALE,
        'language_code':        LOCALE,
        'ford_application_id':  APP_ID,
        'country_code':         COUNTRY,
    }
    auth_url = f'{LOGIN_BASE}/authorize?' + urllib.parse.urlencode(params)

    return render_template_string(AUTH_PAGE,
                                  auth_url=auth_url,
                                  authenticated=bool(_auth['access_token']),
                                  message=None, success=False)

@app.route('/auth/start')
def auth_start():
    """Direct redirect to Ford login — easier than copying a long URL."""
    verifier   = _make_verifier()
    challenge  = _make_challenge(verifier)
    _auth['code_verifier'] = verifier

    params = {
        'redirect_uri':         REDIRECT,
        'response_type':        'code',
        'max_age':              '3600',
        'code_challenge':       challenge,
        'code_challenge_method':'S256',
        'scope':                f'{CLIENT_ID} openid',
        'client_id':            CLIENT_ID,
        'ui_locales':           LOCALE,
        'language_code':        LOCALE,
        'ford_application_id':  APP_ID,
        'country_code':         COUNTRY,
    }
    return redirect(f'{LOGIN_BASE}/authorize?' + urllib.parse.urlencode(params))


@app.route('/auth/complete', methods=['POST'])
def auth_complete():
    redirect_url = request.form.get('redirect_url', '').strip()
    verifier     = _auth.get('code_verifier')

    if not verifier:
        return render_template_string(AUTH_PAGE,
                                      auth_url='', authenticated=False,
                                      message='Session expired — go back to /auth and start again.',
                                      success=False)

    # Extract code from fordapp://userauthorized/?code=XXX
    try:
        parsed = urllib.parse.urlparse(redirect_url)
        code   = urllib.parse.parse_qs(parsed.query).get('code', [None])[0]
        if not code:
            raise ValueError('No code found')
    except Exception:
        return render_template_string(AUTH_PAGE,
                                      auth_url='', authenticated=False,
                                      message='Could not find authorization code in that URL. Make sure you copied the full URL.',
                                      success=False)

    try:
        # Step 3: Exchange code for B2C token
        r = requests.post(TOKEN_URL,
                          headers={**COMMON_HEADERS,
                                   'Content-Type': 'application/x-www-form-urlencoded'},
                          data={
                              'client_id':     CLIENT_ID,
                              'scope':         f'{CLIENT_ID} openid',
                              'redirect_uri':  REDIRECT,
                              'grant_type':    'authorization_code',
                              'code':          code,
                              'code_verifier': verifier,
                          }, timeout=15)
        r.raise_for_status()
        b2c_token = r.json()['access_token']

        # Step 4: Exchange B2C token for Ford API token
        r2 = requests.post(B2C_TOKEN_URL,
                           headers={**COMMON_HEADERS,
                                    'Content-Type': 'application/json',
                                    'Application-Id': APP_ID},
                           json={'idpToken': b2c_token},
                           timeout=15)
        r2.raise_for_status()
        data = r2.json()

        _auth['access_token']  = data['access_token']
        _auth['refresh_token'] = data['refresh_token']
        _auth['expires_at']    = time.time() + int(data.get('expires_in', 1800)) - 60
        _auth['code_verifier'] = None

        return render_template_string(AUTH_PAGE,
                                      auth_url='', authenticated=True,
                                      message='✅ Authentication successful! Your Pebble app is ready.',
                                      success=True)
    except Exception as e:
        return render_template_string(AUTH_PAGE,
                                      auth_url='', authenticated=False,
                                      message=f'Auth failed: {str(e)}',
                                      success=False)


# ── Health ────────────────────────────────────────────────────────────────────
@app.route('/health')
def health():
    return jsonify({'ok': True, 'authenticated': bool(_auth['access_token'])})


# ── Vehicle routes ────────────────────────────────────────────────────────────
@app.route('/status')
@require_api_key
def status():
    try:
        vs = get_vehicle_status()
        return jsonify(parse_status(vs))
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/info')
@require_api_key
def info():
    try:
        vs = get_vehicle_status()
        result = parse_status(vs)
        result.update(parse_info(vs))
        return jsonify(result)
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/lock', methods=['POST'])
@require_api_key
def lock():
    try:
        url = f'{API_BASE}/vehicles/v2/{FORD_VIN}/doors/lock'
        r = requests.put(url, headers=api_headers(), timeout=15)
        r.raise_for_status()
        poll_command(url, r.json().get('commandId'))
        vs = get_vehicle_status()
        result = parse_status(vs)
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
        url = f'{API_BASE}/vehicles/v2/{FORD_VIN}/doors/lock'
        r = requests.delete(url, headers=api_headers(), timeout=15)
        r.raise_for_status()
        poll_command(url, r.json().get('commandId'))
        vs = get_vehicle_status()
        result = parse_status(vs)
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
        url = f'{API_BASE}/vehicles/v2/{FORD_VIN}/engine/start'
        r = requests.put(url, headers=api_headers(), timeout=20)
        r.raise_for_status()
        poll_command(url, r.json().get('commandId'))
        vs = get_vehicle_status()
        result = parse_status(vs)
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
        url = f'{API_BASE}/vehicles/v2/{FORD_VIN}/engine/start'
        r = requests.delete(url, headers=api_headers(), timeout=20)
        r.raise_for_status()
        poll_command(url, r.json().get('commandId'))
        vs = get_vehicle_status()
        result = parse_status(vs)
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
        url = f'{API_BASE}/vehicles/v2/{FORD_VIN}/alert'
        r = requests.put(url, headers=api_headers(), timeout=15)
        r.raise_for_status()
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
    seat    = bool(body.get('seat', False))
    wheel   = bool(body.get('wheel', False))
    defrost = bool(body.get('defrost', False))
    temp    = int(body.get('temp', 72))

    try:
        hdrs = api_headers()

        requests.put(f'{API_BASE}/vehicles/v2/{FORD_VIN}/seatHeat',
                     headers=hdrs,
                     json={'driverSeatHeatLevel':    3 if seat else 0,
                           'passengerSeatHeatLevel': 3 if seat else 0},
                     timeout=15)

        requests.put(f'{API_BASE}/vehicles/v2/{FORD_VIN}/steeringWheelHeat',
                     headers=hdrs,
                     json={'steeringWheelHeat': 'On' if wheel else 'Off'},
                     timeout=15)

        requests.put(f'{API_BASE}/vehicles/v2/{FORD_VIN}/defrost',
                     headers=hdrs,
                     json={'defrostZone': 'FRONT', 'duration': 10 if defrost else 0},
                     timeout=15)

        vs = get_vehicle_status()
        result = parse_status(vs)
        result.update({'climate_temp': temp, 'climate_seat': seat,
                       'climate_wheel': wheel, 'climate_defrost': defrost})
        return jsonify(result)
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 502


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
