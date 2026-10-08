# passkey-gate

A small reverse proxy that puts **passkey (WebAuthn/FIDO2) sign-in** in
front of any self-hosted web app. It works the same way for Jellyfin, n8n,
Grafana, a homemade dashboard or anything else that speaks HTTP and
WebSockets.

```
browser ──HTTPS──▶ your TLS proxy ──▶ passkey-gate:3000 ──▶ app:8080
                   (Caddy, Nginx,       │
                    Traefik,            ├─ no session → login page (browsers) / 401 (API, WebSocket)
                    cloudflared…)       └─ session    → proxied, with clean X-Forwarded-* headers
```

- **Passwordless and phishing-resistant.** Passkeys are bound to your
  domain, user verification (biometric/PIN) is required, and no username
  is typed.
- **Invite-only.** Registration needs a single-use, expiring invite link
  from the admin CLI.
- **Works with any domain and any app.** Everything app-specific comes from
  environment variables, and the gate's own routes live under one prefix
  (`/__passkey` by default) so they can't collide with the app's.
- **Proxies HTTP and WebSockets.** Upgrades are authenticated too.
- **Self-contained.** One SQLite file holds users, passkeys, invites and
  sessions. Nothing is loaded from a CDN.

Built with TypeScript. The server uses Express 5, `@simplewebauthn/server`
v14, `http-proxy-middleware` v4 and `better-sqlite3`. The login page is a
Vue 3 app built with Vite, using `@simplewebauthn/browser` v14.

## Why

Self-hosted apps often end up on the internet with nothing but their own
password form in front of them. That form is a brute-force target, and any
unauthenticated bug in the app is exposed to the whole internet. Full
identity providers (Authelia, Authentik, Keycloak) fix that, but they bring
SSO, OIDC, LDAP, access policies and a database to run and configure.

passkey-gate does one job: nobody reaches the app without a passkey. It's
one container, configured with two environment variables, and invite-only.

## Getting started

### Prerequisites

- **A domain with HTTPS** in front of the gate. Browsers only allow passkeys
  on secure origins (`http://localhost` is the one exception, for testing).
- **A reverse proxy that terminates TLS**, such as Caddy, Nginx, Traefik or
  Cloudflare Tunnel. Ready-made configs are [below](#3-point-your-reverse-proxy-at-the-gate).
- **Docker with Compose v2**, or Node.js 22+ to run it without Docker.
- **A device with passkey support**: any current iPhone/Android, macOS,
  Windows Hello, or a hardware key such as a YubiKey.

### 1. Get the image

Use the published image `ghcr.io/bobbykiselkov/passkey-gate:latest` (or
pin a version tag such as `1.0.0`). To build it yourself instead:

```bash
git clone https://github.com/bobbykiselkov/passkey-gate.git
cd passkey-gate
docker build -t passkey-gate:local .
```

Then use `image: passkey-gate:local`, or `build: .`, in the compose file
below.

### 2. Add the gate next to your app

```yaml
services:
  passkey-gate:
    image: ghcr.io/bobbykiselkov/passkey-gate:latest
    container_name: passkey-gate
    restart: unless-stopped
    environment:
      ORIGIN: https://media.example.com   # exactly what people type in the address bar
      UPSTREAM_URL: http://jellyfin:8096  # the app, as seen from this container
      APP_NAME: Jellyfin
      TRUST_PROXY: 1                      # one reverse proxy in front of the gate
    volumes:
      - passkey-gate-data:/data
    expose: ["3000"]                      # NOT `ports:`, only the reverse proxy reaches it

  jellyfin:
    image: jellyfin/jellyfin
    expose: ["8096"]                      # remove any public `ports:` mapping from the app

volumes:
  passkey-gate-data:
```

```bash
docker compose up -d
docker compose logs passkey-gate   # "passkey-gate listening on :3000 → http://jellyfin:8096 …"
```

The gate and the app must share a Docker network. Services in the same
compose file do this automatically. Every option is in the
[configuration table](#configuration) and in [`.env.example`](.env.example).

### 3. Point your reverse proxy at the gate

Send the app's hostname to `passkey-gate:3000` instead of to the app. The
proxy has to pass WebSocket upgrades and the usual `X-Forwarded-*` headers.

<details open>
<summary><b>Caddy</b></summary>

```caddyfile
media.example.com {
	reverse_proxy passkey-gate:3000
}
```

Caddy handles TLS, WebSockets and `X-Forwarded-*` on its own.
</details>

<details>
<summary><b>Nginx</b></summary>

```nginx
server {
    listen 443 ssl;
    server_name media.example.com;
    # ssl_certificate / ssl_certificate_key …

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:3000;   # or http://passkey-gate:3000 if Nginx runs in Docker
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_buffering off;                # stream media/large responses immediately
    }
}

# in the http {} block:
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

If Nginx runs on the host and not in Docker, publish the gate on loopback
only: `ports: ["127.0.0.1:3000:3000"]`.
</details>

<details>
<summary><b>Traefik</b></summary>

```yaml
  passkey-gate:
    # …as above, plus:
    labels:
      traefik.enable: "true"
      traefik.http.routers.media.rule: Host(`media.example.com`)
      traefik.http.routers.media.entrypoints: websecure
      traefik.http.routers.media.tls.certresolver: letsencrypt
      traefik.http.services.media.loadbalancer.server.port: "3000"
```
</details>

<details>
<summary><b>Cloudflare Tunnel</b></summary>

In Zero Trust → Networks → Tunnels → your tunnel → Public Hostname, set the
hostname's service to `http://passkey-gate:3000`. `cloudflared` must be on
the same Docker network. Keep `TRUST_PROXY=1`.
</details>

Only one proxy in front of the gate means `TRUST_PROXY=1`. For a chain
(e.g. Cloudflare → Nginx → gate), set it to the number of hops.

### 4. Create the first account

```bash
docker exec -it passkey-gate passkey-gate invite
```

This prints a single-use link such as
`https://media.example.com/__passkey/login?invite=…`. Open it, choose a
username, and confirm the passkey prompt with Face ID, Touch ID, Windows
Hello, your phone or a security key. You're signed in and sent to the app.

Invite other people the same way, and send the link over a private
channel. See the [admin CLI](#admin-cli) for adding devices and removing
users.

### 5. Tell the app to trust the gate

The app sees every request coming from the gate, so its trusted-proxy
setting should include the gate (`passkey-gate`, or the container's IP).
That way it logs real client IPs and doesn't treat every user as one
client for rate-limiting. For example: Jellyfin's *Dashboard → Networking →
Known proxies*, or Nextcloud's `trusted_proxies`.

### 6. Check that it's working

- [ ] In a private window, `https://media.example.com` redirects to
      `/__passkey/login`, not to the app.
- [ ] `curl -i https://media.example.com/` returns `302` (or `401` with
      `-H 'Accept: application/json'`).
- [ ] After signing in, the app loads, and live features that use
      WebSockets work.
- [ ] The app is **not** reachable around the gate: its old port or
      hostname times out or is refused.
- [ ] `docker inspect --format '{{.State.Health.Status}}' passkey-gate`
      shows `healthy`.

### Running without Docker

```bash
git clone https://github.com/bobbykiselkov/passkey-gate.git && cd passkey-gate
npm ci && npm run build && npm prune --omit=dev

export ORIGIN=https://media.example.com UPSTREAM_URL=http://127.0.0.1:8096 \
       APP_NAME=Jellyfin DATA_DIR=/var/lib/passkey-gate HOST=127.0.0.1 PORT=3000
node dist/server.js
node dist/cli.js invite      # in another shell, with the same env
```

As a systemd service (`/etc/systemd/system/passkey-gate.service`):

```ini
[Unit]
Description=passkey-gate
After=network-online.target

[Service]
WorkingDirectory=/opt/passkey-gate
ExecStart=/usr/bin/node dist/server.js
EnvironmentFile=/etc/passkey-gate.env
User=passkey-gate
StateDirectory=passkey-gate
Environment=DATA_DIR=/var/lib/passkey-gate
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

`HOST=127.0.0.1` in `/etc/passkey-gate.env` keeps it on loopback, so
the reverse proxy on the same machine is the only way in.

### Protecting several apps

Run one gate per app. Give each its own `ORIGIN`, `UPSTREAM_URL`,
container name and data volume. Users and invites are per gate.

## Configuration

| Variable | Default | |
|---|---|---|
| `ORIGIN` | **required** | Exact public origin, e.g. `https://media.example.com`. WebAuthn checks it on every sign-in. |
| `UPSTREAM_URL` | **required** | Where authenticated traffic goes, e.g. `http://app:8080`. |
| `APP_NAME` | `Protected app` | Shown on the login page. |
| `RP_ID` | `ORIGIN`'s hostname | Passkey domain. Can be a parent domain to share passkeys across subdomains. **Changing it invalidates every passkey.** |
| `RP_NAME` | `APP_NAME` | Shown in the browser's passkey prompt. |
| `SESSION_SECRET` | generated into `DATA_DIR/session-secret` | Signs session cookies. At least 32 characters. |
| `SESSION_TTL_DAYS` | `30` | Sign-in lifetime, absolute from sign-in. |
| `INVITE_TTL_HOURS` | `72` | Default invite link lifetime. |
| `TRUST_PROXY` | `1` | Number of reverse proxies in front of the gate. See [security](#security). |
| `GATE_PREFIX` | `/__passkey` | Path prefix for the gate's login page, assets and API. |
| `PUBLIC_PATHS` | — | Comma-separated path prefixes proxied **without** a session, e.g. `/webhook/,/healthz`. |
| `UPSTREAM_USER_HEADER` | — | Send the signed-in username upstream in this header, e.g. `X-Remote-User`. |
| `DATA_DIR` | `/data` (image), `./data` (source) | Where `gate.db` and the generated secret live. |
| `PORT` | `3000` | Listen port. |
| `HOST` | all interfaces | Listen address, e.g. `127.0.0.1` when running outside Docker. |
| `COOKIE_SECURE` | `true` | Set `false` only for testing on plain `http://localhost`. |

### `PUBLIC_PATHS`

These are for clients that can't sign in: webhooks, uptime checks and
public share links. Matching is case-sensitive and fails closed. A request
whose raw path contains `..`, encoded slashes (`%2F`, `%5C`) or backslashes
is never treated as public, because the app might normalize it to a
different path than the gate checked. A trailing `/` matches everything
under it (`/webhook/` → `/webhook/abc`). Without one, the entry matches the
path itself and anything below it (`/healthz`, `/healthz/live`).

### `UPSTREAM_USER_HEADER`

For apps with trusted-header SSO (Grafana `auth.proxy`, Nextcloud, Paperless
and others): the gate sets this header to the signed-in username, and always
strips any value the client sent. Only enable it if the app can't be reached
except through the gate. Otherwise anyone could send the header directly.

## Admin CLI

Inside the container, `passkey-gate` is on the `PATH`:

```bash
passkey-gate invite                     # new user, link valid INVITE_TTL_HOURS
passkey-gate invite --hours 24
passkey-gate invite --user alice        # add a passkey to alice (new device / lost phone)
passkey-gate invites                    # open invites
passkey-gate revoke-invites
passkey-gate users
passkey-gate delete-user alice          # passkeys gone, open sessions cut off immediately
```

Each invite is 32 random bytes, single-use and time-limited. Only its
SHA-256 is stored, and the invite is consumed in the same transaction that
stores the passkey.

## Routes

Everything below lives under `GATE_PREFIX`. Everything else is proxied.

| Route | |
|---|---|
| `GET  /login` | Login page. `?next=/path` sets where to return after sign-in. `?invite=TOKEN` shows registration. |
| `GET  /health` | `ok`, for container health checks. Unauthenticated. |
| `GET  /assets/*` | The login page's built JS/CSS (content-hashed, cached for a year). |
| `GET  /api/session` | `{ authenticated, username }` |
| `GET  /api/invite?token=` | `{ valid, forUsername }` |
| `GET  /api/generate-auth-options` | WebAuthn authentication options. The challenge is stored in the session. |
| `POST /api/verify-auth` | Verifies the assertion, updates the signature counter and starts a session. |
| `GET  /api/generate-reg-options?token=&username=` | Registration options. Needs a valid invite. |
| `POST /api/verify-reg` | Verifies the attestation, stores the passkey, consumes the invite and starts a session. |
| `POST /api/logout` | Ends the session. |

Unauthenticated `GET`/`HEAD` requests that accept HTML get a `302` to the
login page. Everything else gets a `401`, and WebSocket upgrades are refused
with `401`.

## Security

- **Terminate HTTPS in front of the gate.** WebAuthn only works on secure
  origins, and the session cookie is `Secure`, `HttpOnly`, `SameSite=Lax`
  and `__Host-` prefixed. The gate learns the request was HTTPS from
  `X-Forwarded-Proto`, which it only believes when `TRUST_PROXY` ≥ 1.
- **Set `TRUST_PROXY` to the real number of proxy hops.** If it's too low,
  no cookie is ever set and sign-in loops. If it's too high, clients can
  spoof their IP (`X-Forwarded-For`) past the rate limiter.
- **Never publish the gate's port, and don't leave the app reachable
  around it.** The gate is only a boundary if it's the only way in.
- **Make the upstream trust the gate.** The gate collapses
  `X-Forwarded-For` to the one resolved client IP and sets
  `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Real-IP`, so the app only
  needs the gate in its trusted-proxy list. For Jellyfin, that's
  *Dashboard → Networking → Known proxies*. Otherwise the app sees every
  user as the gate's IP, and any per-IP lockout it has treats them all as
  one client.
- **What's enforced:**
  - User verification is required.
  - Credentials are discoverable, so there's no username enumeration.
  - Challenges are single-use and expire after 5 minutes.
  - Sign-in rotates the session ID (no session fixation).
  - Signature-counter regressions are rejected.
  - `/api` is rate-limited to 100 requests per 15 minutes per IP.
  - Cross-origin POSTs are refused.
  - `?next=` only accepts same-origin paths.
  - The gate's cookie is stripped before proxying.
  - Deleting a user cuts off their sessions on their next request.
  - The login page runs under `script-src 'self'` with no inline scripts.
- **Sessions are absolute.** Proxied traffic doesn't extend them, so it
  never writes to the database. Pre-sign-in sessions are pruned after 10
  minutes.
- **Back up `/data`.** Losing `gate.db` means everyone has to be invited
  again. It holds public keys and hashes only, so a leaked copy can't be
  used to sign in.

### Limitations

- **Native apps can't sign in** (TV apps, mobile clients, desktop players,
  CLI tools), because they don't render a web login page. Give them another
  way in, such as a VPN or LAN-only port, or for webhook-style traffic,
  `PUBLIC_PATHS`.
- The gate controls *who reaches the app*. The app's own accounts still
  control what each person can do there.
- `npm audit` flags `braces` (via `micromatch` ← `http-proxy-middleware`)
  for a ReDoS in deeply nested glob patterns. It's unreachable here: the
  gate never passes request data to glob matching, and no fixed release
  exists yet.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Sign-in "succeeds" but you land back on the login page | No session cookie was set: the gate doesn't think the request was HTTPS. Check that the proxy sends `X-Forwarded-Proto: https` and that `TRUST_PROXY` ≥ 1. |
| "This address doesn't match the server's passkey domain" | `ORIGIN`/`RP_ID` don't match the URL in the address bar. Fix `ORIGIN` exactly: scheme, host and port. |
| Passkey prompt never appears | The page isn't on HTTPS (or `localhost`), or the browser/device has no passkey support. |
| "This passkey isn't registered here" | The passkey belongs to another gate or a deleted user, or `RP_ID` changed. Get a new invite. |
| App loads but live updates/streams break | The proxy isn't forwarding WebSocket upgrades. See the Nginx `Upgrade`/`Connection` headers above. |
| `502 … is unreachable` | The gate can't reach `UPSTREAM_URL`. Check the app is running and on the same Docker network. |
| `SQLITE_CANTOPEN` / permission denied on start | The data directory isn't writable by the container user (uid 1000). Use a named volume, or `chown 1000:1000` the bind-mounted folder. |
| Every user shows the same IP in the app's logs | The app doesn't trust the gate yet. See [step 5](#5-tell-the-app-to-trust-the-gate). |

The gate logs every sign-in, registration and failed verification with
the client IP: `docker compose logs -f passkey-gate`.

## Upgrading and backups

```bash
docker compose pull passkey-gate && docker compose up -d passkey-gate
```

The database schema is created and kept up to date on start. Back up the
`/data` volume (`gate.db`, plus `session-secret` if you didn't set
`SESSION_SECRET`). Restoring it brings back all users and passkeys.
Sessions survive restarts and upgrades.

## Local development

### Prerequisites

- **Node.js 22+** (`node -v`) and npm.
- **A browser with passkey support.** Chrome, Edge, Safari and Firefox all
  work. You don't need a real passkey device; see
  [step 5](#5-sign-in-with-a-passkey).
- Usually nothing else. `better-sqlite3` ships prebuilt binaries. If
  `npm ci` falls back to compiling it, install the platform build tools
  (`xcode-select --install` on macOS, `build-essential python3` on
  Debian/Ubuntu).

### 1. Install

```bash
git clone https://github.com/bobbykiselkov/passkey-gate.git
cd passkey-gate
npm ci
```

### 2. Configure `.env`

```bash
cp .env.example .env
```

Then set these local values in `.env`:

```ini
ORIGIN=http://localhost:3000
UPSTREAM_URL=http://127.0.0.1:8080
APP_NAME=Local test
COOKIE_SECURE=false
TRUST_PROXY=0
```

Why each one matters:

- **`ORIGIN` must be `http://localhost:<port>`.** Browsers allow WebAuthn on
  `http://localhost`, but on no other plain-HTTP origin. A production
  origin such as `https://media.example.com` will start, but passkeys won't
  work from localhost, because the browser checks that the page's address
  matches.
- **`COOKIE_SECURE=false`.** Otherwise the session cookie is HTTPS-only and
  never sticks on `http://localhost`.
- **`TRUST_PROXY=0`.** Nothing sits in front of the gate locally.
- **`UPSTREAM_URL` must point at something running on your machine.** Docker
  service names like `http://app:8080` don't resolve outside Docker.

`./.env` is loaded automatically when running from source (`npm run dev`,
`npm start` and the CLI). Set `ENV_FILE=path/to/file` to use a different
file. Variables already set in your shell take precedence over the file.

### 3. Start something to protect

Any local web app works, such as a dev server, a local Jellyfin, or this
one-liner, which serves the current directory on port 8080:

```bash
python3 -m http.server 8080
```

### 4. Start the gate

In a second terminal:

```bash
npm run dev
# [client] built in 150ms.
# [server] passkey-gate listening on :3000 → http://127.0.0.1:8080 (origin http://localhost:3000, …)
```

`npm run dev` runs two watchers side by side:

- **`[client]`** is `vite build --watch`. It rebuilds the Vue login page
  into `dist/public` whenever something in `client/` changes. Reload the
  browser to see the change. The server picks up the new build by itself.
- **`[server]`** is `tsx watch`. It restarts the server whenever a file in
  `src/` changes.

The login page is served through the gate (not a Vite dev server)
because passkeys only work on the exact `ORIGIN`, and the page needs the
gate's session cookie and API on the same origin.

### 5. Sign in with a passkey

Create an invite in a third terminal:

```bash
npx tsx src/cli.ts invite
# http://localhost:3000/__passkey/login?invite=…
```

Open the link, pick a username and click **Register Passkey**. After the
passkey prompt you're sent to `http://localhost:3000/`, which now shows the
upstream app.

To test without saving passkeys to your real keychain or phone, use
Chrome's virtual authenticator: open DevTools → ⋮ → **More tools →
WebAuthn** → tick **Enable virtual authenticator environment** → **Add**.
Use the defaults, with *Supports resident keys* and *Supports user
verification* both ticked. Passkeys created this way live in that DevTools
panel and disappear when you close it. If you used your real keychain
instead, the test passkey shows up for `localhost` in your password
manager (macOS: *Passwords* app) and can be deleted there.

Useful while testing:

```bash
npx tsx src/cli.ts users
npx tsx src/cli.ts invite --user <name>   # add a second device
curl -i http://localhost:3000/            # 302 to the login page when signed out
```

Sign out with the **Sign out** button at `http://localhost:3000/__passkey/login`.

### 6. Tests, typecheck and production build

```bash
npm test            # end-to-end suite: real gate + fake upstream + software authenticator
npm run typecheck   # server, client and tests
npm run build       # → dist/
npm start           # runs dist/server.js (also reads .env)
node dist/cli.js invite
```

The test suite uses its own temporary data directory. It never touches
`./data` or your `.env`.

TypeScript is pinned to 6.0 on purpose. `vue-tsc`, which type-checks the
`.vue` files, needs the compiler's JavaScript API, and TypeScript 7 (the
Go-based compiler) doesn't have one. Don't move to 7 until `vue-tsc`
supports it.

### Run the Docker image locally

```bash
docker build -t passkey-gate:local .
docker run --rm -p 3000:3000 \
  -e ORIGIN=http://localhost:3000 \
  -e UPSTREAM_URL=http://host.docker.internal:8080 \
  -e COOKIE_SECURE=false -e TRUST_PROXY=0 \
  -v passkey-gate-dev:/data --name passkey-gate passkey-gate:local

docker exec -it passkey-gate passkey-gate invite
```

`host.docker.internal` reaches services on your machine from inside the
container. It works out of the box on Docker Desktop; on Linux, add
`--add-host=host.docker.internal:host-gateway`. The image doesn't read
`.env`, so pass settings with `-e` or `--env-file .env`.

### Resetting local state

All local state (users, passkeys, invites, sessions, the generated session
secret) lives in `./data`:

```bash
rm -f data/gate.db* data/session-secret   # keeps data/.gitkeep
```

### Project layout

```
src/
  server.ts   entry point
  app.ts      routes, auth check, HTTP + WebSocket proxy
  config.ts   environment → validated config
  db.ts       SQLite schema, queries, session store
  cli.ts      admin CLI
client/                 Vue login page (Vite root) → dist/public
  index.html            page template ({{APP_NAME}}, {{PREFIX}} filled in by the server)
  src/
    main.ts             app entry
    App.vue             page state: loading / signed in / sign in + invite
    style.css           theme tokens and base styles
    components/         BrandHeader, StatusBanner, PasskeyButton,
                        SignedInCard, RegisterForm
    lib/
      passkey.ts        WebAuthn ceremonies (@simplewebauthn/browser), session calls
      api.ts            fetch wrapper for the gate's API
      config.ts         reads the prefix and app name from <meta> tags
vite.config.ts
test/
  e2e.test.ts
```

CI (`.github/workflows/ci.yml`) typechecks and tests every push and PR. On
pushes to `main` and `v*` tags, it also publishes a multi-arch image
(`linux/amd64`, `linux/arm64`) to `ghcr.io/<owner>/passkey-gate`.
