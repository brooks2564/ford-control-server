"""
Ford Control Server — Flask middleware for Pebble Ford Control watchapp.
Credentials and API key stored as Render environment variables.

WARNING: This uses an unofficial FordPass API. Ford monitors for unusual
traffic and may temporarily lock your account. Use at your own risk.
"""

import os, time, json, requests
from flask import Flask, jsonify, request

app = Flask(__name__)

FORD_EMAIL    = os.environ.get('FORD_EMAIL', '')
FORD_PASSWORD = os.environ.get('FORD_PASSWORD', '')
FORD_VIN      = os.environ.get('FORD_VIN', '').upper()
API_KEY       = os.environ.get('FORD_API_KEY', 'changeme')

# ── FordPass API constants ────────────────────────────────────────────────────
APP_ID       = '71A3AD0A-CF46-4CCF-B473-FC7FE5BC4592'
USER_AGENT   = 'fordpass-na/353 CFNetwork/1197 Darwin/20.0.0'
AUTH_URL     = 'https://fcis.ice.ibmcloud.com/v1.0/endpoint/default/token'
API_BASE     = 'https://usapi.cv.ford.com/api'
VEHICLE_BASE = f'{API_BASE}/vehicles/{FORD_VIN}'

# Token cache
_token_cache = {'access_token': None, 'expires_at': 0}


def get_token():
    now = time.time()
    if _token_cache['access_token'] and now < _token_cache['expires_at'] - 30:
        return _token_cache['access_token']

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*',
    }
    data = {
        'client_id': '9fb503e0-715b-47e8-adfd-ad4b7770f73b',
        'grant_type': 'password',
        'username': FORD_EMAIL,
        'password': FORD_PASSWORD,
    }
    r = requests.post(AUTH_URL, headers=headers, data=data, timeout=15)
    r.raise_for_status()
    result = r.json()
    _token_cache['access_token'] = result['access_token']
    _token_cache['expires_at'] = now + int(result.get('expires_in', 290))
    return _token_cache['access_token']


def ford_headers():
    return {
        'Application-Id': APP_ID,
        'auth-token': get_token(),
        'Content-Type': 'application/json',
        'Accept': '*/*',
        'User-Agent': USER_AGENT,
    }


def require_api_key(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get('X-API-Key') != API_KEY:
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


def parse_status(raw):
    vs = raw.get('vehiclestatus', raw)
    locked  = vs.get('lockStatus', {}).get('value', 'LOCKED').upper() == 'LOCKED'
    running = vs.get('ignitionStatus', {}).get('value', 'Off').lower() != 'off'
    model   = raw.get('nickName') or raw.get('modelName') or 'Maverick'

    result = {
        'is_locked':  locked,
        'is_running': running,
        'model_name': model,
    }
    return result


def parse_info(raw):
    vs = raw.get('vehiclestatus', raw)

    fuel = None
    fuel_data = vs.get('fuel', vs.get('fuelLevel'))
    if fuel_data:
        fuel = int(fuel_data.get('fuelLevel', fuel_data.get('value', -1)))

    oil = None
    oil_data = vs.get('oil', vs.get('oilLife'))
    if oil_data:
        oil = int(oil_data.get('oilLifeActual', oil_data.get('value', -1)))

    tires = vs.get('TPMS', vs.get('tirePressure', {}))
    def get_psi(key):
        val = tires.get(key, {})
        if isinstance(val, dict):
            v = val.get('value', -1)
        else:
            v = val
        try:
            return int(float(v) * 0.145038)  # kPa -> psi
        except Exception:
            return -1

    return {
        'fuel_level': fuel,
        'oil_life':   oil,
        'tire_fl':    get_psi('leftFrontTirePressure'),
        'tire_fr':    get_psi('rightFrontTirePressure'),
        'tire_rl':    get_psi('leftRearTirePressure'),
        'tire_rr':    get_psi('rightRearTirePressure'),
    }


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/health')
def health():
    return jsonify({'ok': True})


@app.route('/status')
@require_api_key
def status():
    try:
        r = requests.get(f'{VEHICLE_BASE}/status', headers=ford_headers(), timeout=15)
        r.raise_for_status()
        return jsonify(parse_status(r.json()))
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/info')
@require_api_key
def info():
    try:
        r = requests.get(f'{VEHICLE_BASE}/status', headers=ford_headers(), timeout=15)
        r.raise_for_status()
        data = r.json()
        result = parse_status(data)
        result.update(parse_info(data))
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/lock', methods=['POST'])
@require_api_key
def lock():
    try:
        r = requests.put(f'{VEHICLE_BASE}/doors/lock', headers=ford_headers(), timeout=15)
        r.raise_for_status()
        time.sleep(2)
        s = requests.get(f'{VEHICLE_BASE}/status', headers=ford_headers(), timeout=15)
        result = parse_status(s.json())
        result['is_locked'] = True
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/unlock', methods=['POST'])
@require_api_key
def unlock():
    try:
        r = requests.delete(f'{VEHICLE_BASE}/doors/lock', headers=ford_headers(), timeout=15)
        r.raise_for_status()
        time.sleep(2)
        s = requests.get(f'{VEHICLE_BASE}/status', headers=ford_headers(), timeout=15)
        result = parse_status(s.json())
        result['is_locked'] = False
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/start', methods=['POST'])
@require_api_key
def start():
    try:
        r = requests.put(f'{VEHICLE_BASE}/engine/start', headers=ford_headers(), timeout=20)
        r.raise_for_status()
        time.sleep(3)
        s = requests.get(f'{VEHICLE_BASE}/status', headers=ford_headers(), timeout=15)
        result = parse_status(s.json())
        result['is_running'] = True
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/stop', methods=['POST'])
@require_api_key
def stop():
    try:
        r = requests.delete(f'{VEHICLE_BASE}/engine/start', headers=ford_headers(), timeout=20)
        r.raise_for_status()
        time.sleep(2)
        s = requests.get(f'{VEHICLE_BASE}/status', headers=ford_headers(), timeout=15)
        result = parse_status(s.json())
        result['is_running'] = False
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/find', methods=['POST'])
@require_api_key
def find():
    try:
        # Panic / horn + lights flash
        r = requests.put(f'{VEHICLE_BASE}/alert', headers=ford_headers(), timeout=15)
        r.raise_for_status()
        return jsonify({'ok': True, 'is_locked': True, 'is_running': False})
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/climate', methods=['POST'])
@require_api_key
def climate():
    body = request.get_json() or {}
    temp    = int(body.get('temp', 72))
    seat    = bool(body.get('seat', False))
    wheel   = bool(body.get('wheel', False))
    defrost = bool(body.get('defrost', False))

    try:
        headers = ford_headers()
        results = {}

        # Seat heaters
        seat_payload = {
            'driverSeatHeatLevel':    3 if seat else 0,
            'passengerSeatHeatLevel': 3 if seat else 0,
        }
        r = requests.put(f'{VEHICLE_BASE}/seatHeat', headers=headers,
                         json=seat_payload, timeout=15)
        results['seat'] = r.status_code

        # Steering wheel heat
        wheel_payload = {'steeringWheelHeat': 'On' if wheel else 'Off'}
        r = requests.put(f'{VEHICLE_BASE}/steeringWheelHeat', headers=headers,
                         json=wheel_payload, timeout=15)
        results['wheel'] = r.status_code

        # Front defrost
        defrost_payload = {'defrostZone': 'FRONT', 'duration': 10 if defrost else 0}
        r = requests.put(f'{VEHICLE_BASE}/defrost', headers=headers,
                         json=defrost_payload, timeout=15)
        results['defrost'] = r.status_code

        s = requests.get(f'{VEHICLE_BASE}/status', headers=headers, timeout=15)
        result = parse_status(s.json())
        result['climate_temp']    = temp
        result['climate_seat']    = seat
        result['climate_wheel']   = wheel
        result['climate_defrost'] = defrost
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 502


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
