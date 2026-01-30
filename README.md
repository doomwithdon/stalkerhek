This fork of the original StalkerHek allows connecting with no authentication or authetication using Device IDs when username and password are not provided.

# Stalkerhek

Stalkerhek is a proxy application that allows you to share the same Stalker portal account on (theoretically) unlimited amount of STB boxes and makes it possible to watch Stalker portal IPTV streams in simple video players, such as VLC. This application itself connects to Stalker portal, authenticates with it and keeps sending keep-alive requests to remain connected. The rest is being done by this application's [Services](https://github.com/CrazeeGhost/stalkerhek/wiki/Services#proxy-service).

See [Stalkerhek Documentation](https://github.com/CrazeeGhost/stalkerhek/wiki).

## Administrative UI

If `admin.enabled: true`, a minimal web UI is started at the configured `bind` address. It lets you edit portal settings at runtime and trigger a restart (the process will exit and your supervisor should restart it).

## Cloudflare-protected portals

If your portal (or stream URLs) are behind Cloudflare or similar protection:

1. **Configure** in `stalkerhek.yml`:
   - `portal.cookies`: a valid `cf_clearance=...` (and any other cookies) from a browser that passed the challenge.
   - `portal.user_agent`: the same browser’s User-Agent (must match the session that obtained the cookie).

2. **Behaviour**:
   - Portal API, proxy, and HLS stream/logo fetches all use these headers.
   - Requests use a browser-like UA, `Accept`/`Accept-Language`, and optional `Referer` (portal origin).
   - On 403/503 with Cloudflare-related headers (`CF-RAY`, `Server: cloudflare`), requests are retried up to 3 times with exponential backoff (3s, 6s, 12s).
   - HTML responses from auth/handshake are treated as blocked and rejected with a clear error.
