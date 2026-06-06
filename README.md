# Ford Control Server

Flask middleware for the Pebble Ford Control watchapp.

> **Security Warning:** This uses the unofficial FordPass API. Ford's security
> team monitors for non-official API traffic and may temporarily lock your
> account. Use at your own risk.

## Deploy to Render

1. Push this repo to GitHub
2. Go to render.com → New Web Service → connect this repo
3. Set environment variables:
   - `FORD_EMAIL` — your FordPass email
   - `FORD_PASSWORD` — your FordPass password
   - `FORD_VIN` — your vehicle VIN
   - `FORD_API_KEY` — a secret string (set same value in pkjs/index.js)
4. Deploy. Copy the `.onrender.com` URL into `src/pkjs/index.js` `SERVER_URL`

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| GET | /status | Vehicle lock/engine state |
| GET | /info | Fuel, oil, tire pressures |
| POST | /lock | Lock doors |
| POST | /unlock | Unlock doors |
| POST | /start | Remote start engine |
| POST | /stop | Stop engine |
| POST | /find | Panic — horn + lights |
| POST | /climate | Set seat/wheel/defrost heat |

All endpoints except /health require `X-API-Key` header matching `FORD_API_KEY`.
