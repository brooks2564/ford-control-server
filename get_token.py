"""
Run this script ONCE on your local machine to get your Ford refresh token.
Then set FORD_REFRESH_TOKEN in Render environment variables.

Usage: python3 get_token.py
Requires: pip install requests
"""

import os, hashlib, base64, urllib.parse, webbrowser, requests

OAUTH_ID   = '4566605f-43a7-400a-946e-89cc9fdb0bd7'
CLIENT_ID  = '09852200-05fd-41f6-8c21-d36d3497dc64'
APP_ID     = '71A3AD0A-CF46-4CCF-B473-FC7FE5BC4592'
LOCALE     = 'en-US'
REDIRECT   = 'fordapp://userauthorized'
LOGIN_BASE = f'https://login.ford.com/{OAUTH_ID}/B2C_1A_SignInSignUp_{LOCALE}/oauth2/v2.0'
B2C_URL    = 'https://api.foundational.ford.com/api/token/v2/cat-with-b2c-access-token'
HEADERS    = {'Accept-Encoding': 'gzip', 'Connection': 'keep-alive', 'User-Agent': 'okhttp/4.12.0'}

def make_verifier():
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode()

def make_challenge(v):
    return base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()

verifier  = make_verifier()
challenge = make_challenge(verifier)

params = {
    'redirect_uri':          REDIRECT,
    'response_type':         'code',
    'max_age':               '3600',
    'code_challenge':        challenge,
    'code_challenge_method': 'S256',
    'scope':                 f'{CLIENT_ID} openid',
    'client_id':             CLIENT_ID,
    'ui_locales':            LOCALE,
    'language_code':         LOCALE,
    'ford_application_id':   APP_ID,
    'country_code':          'USA',
}
auth_url = f'{LOGIN_BASE}/authorize?' + urllib.parse.urlencode(params)

print("\n=== Ford Control — Token Setup ===\n")
print("1. Opening Ford login in your browser...")
print("   If it doesn't open, visit this URL manually:\n")
print(f"   {auth_url}\n")
webbrowser.open(auth_url)

print("2. Log in with your FordPass email and password.")
print()
print("3. After login, your browser will try to open fordapp://")
print("   - Firefox: shows 'protocol not associated' error — copy the URL from the error page")
print("   - Chrome:  open DevTools (F12) → Network tab → check 'Preserve log'")
print("              then log in and find the fordapp:// request in the log")
print("   - Edge:    similar to Chrome, use DevTools")
print()
redirect_url = input("4. Paste the full fordapp:// URL here: ").strip()

# Extract code
parsed = urllib.parse.urlparse(redirect_url)
code   = urllib.parse.parse_qs(parsed.query).get('code', [None])[0]
if not code:
    print("\nERROR: Could not find authorization code in that URL.")
    print("Make sure you copied the full fordapp://userauthorized/?code=... URL")
    exit(1)

print("\nExchanging code for tokens...")

# Step 1: code → B2C token
r = requests.post(f'{LOGIN_BASE}/token',
                  headers={**HEADERS, 'Content-Type': 'application/x-www-form-urlencoded'},
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

# Step 2: B2C token → Ford API token
r2 = requests.post(B2C_URL,
                   headers={**HEADERS, 'Content-Type': 'application/json',
                             'Application-Id': APP_ID},
                   json={'idpToken': b2c_token}, timeout=15)
r2.raise_for_status()
data = r2.json()

print("\n✅ SUCCESS!\n")
print("Copy this refresh token and add it to Render as FORD_REFRESH_TOKEN:\n")
print(f"  {data['refresh_token']}\n")
print("In Render: your service → Environment → Add Variable")
print("  Key:   FORD_REFRESH_TOKEN")
print(f"  Value: {data['refresh_token']}")
print()
print("Then redeploy your service — no more browser login needed.")
