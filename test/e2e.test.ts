// End-to-end tests: a real gate in front of a fake upstream (HTTP +
// WebSocket), driven by a software authenticator that produces genuine
// WebAuthn registration and assertion responses.

import assert from 'node:assert/strict';
import { type JsonWebKey, type KeyObject, createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';

import { encodeCBOR } from '@levischuck/tiny-cbor';
import WebSocket, { WebSocketServer } from 'ws';

import { type Gate, createGate } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { GateDB, LastAdminError } from '../src/db.js';
import Database from 'better-sqlite3';

const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const sha256 = (b: string | Uint8Array) => createHash('sha256').update(b).digest();

// ---- fake upstream ---------------------------------------------------------

let upstream: http.Server;
let upstreamPort: number;

function startUpstream(): Promise<void> {
  upstream = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ url: req.url, headers: req.headers }));
  });
  new WebSocketServer({ server: upstream }).on('connection', (ws, req) => {
    ws.send(JSON.stringify({ url: req.url, headers: req.headers }));
  });
  return new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
}

// ---- gate + client ---------------------------------------------------------

let gate: Gate;
let db: GateDB;
let base: string;
let dataDir: string;
const PREFIX = '/__passkey';

class Client {
  cookie = '';

  async call(
    urlPath: string,
    { method = 'GET', body, origin = base, accept = 'application/json', headers = {} }: {
      method?: string;
      body?: unknown;
      origin?: string;
      accept?: string;
      headers?: Record<string, string>;
    } = {},
  ) {
    const res = await fetch(base + urlPath, {
      method,
      redirect: 'manual',
      headers: {
        ...(this.cookie ? { cookie: this.cookie } : {}),
        origin,
        accept,
        'content-type': 'application/json',
        'x-forwarded-for': '203.0.113.7',
        'x-forwarded-proto': 'https',
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) this.cookie = setCookie.split(';')[0]!;
    const text = await res.text();
    let json: any;
    try {
      json = JSON.parse(text);
    } catch {
      json = text;
    }
    return { status: res.status, json, headers: res.headers };
  }

  ws(urlPath = '/socket', headers: Record<string, string> = {}): Promise<{ ok: true; data: any } | { ok: false; status: number }> {
    return new Promise((resolve) => {
      const socket = new WebSocket(base.replace('http', 'ws') + urlPath, {
        headers: { ...(this.cookie ? { cookie: `${this.cookie}; other=1` } : {}), ...headers },
      });
      socket.on('message', (m) => {
        resolve({ ok: true, data: JSON.parse(String(m)) });
        socket.close();
      });
      socket.on('unexpected-response', (_req, res) => resolve({ ok: false, status: res.statusCode ?? 0 }));
      socket.on('error', () => resolve({ ok: false, status: 0 }));
    });
  }
}

/** Minimal software passkey: ES256, "none" attestation, UV flag set. */
class SoftAuthenticator {
  readonly credId = randomBytes(16);
  readonly privateKey: KeyObject;
  readonly publicJwk: JsonWebKey;
  counter = 0;
  userHandle = '';

  constructor(readonly rpID: string) {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = pair.privateKey;
    this.publicJwk = pair.publicKey.export({ format: 'jwk' });
  }

  register(options: { challenge: string; user: { id: string } }, origin: string) {
    this.userHandle = options.user.id;
    const cose = encodeCBOR(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(this.publicJwk.x!, 'base64url')],
        [-3, Buffer.from(this.publicJwk.y!, 'base64url')],
      ]),
    );
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credId.length);
    // flags: UP | UV | AT
    const authData = Buffer.concat([sha256(this.rpID), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), idLen, this.credId, cose]);
    const attestationObject = encodeCBOR(
      new Map<string, unknown>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]) as never,
    );
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin }));
    return {
      id: b64u(this.credId),
      rawId: b64u(this.credId),
      type: 'public-key',
      response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject), transports: ['internal'] },
      clientExtensionResults: {},
    };
  }

  authenticate(options: { challenge: string }, origin: string) {
    this.counter++;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    const authData = Buffer.concat([sha256(this.rpID), Buffer.from([0x05]), counter]); // UP | UV
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin }));
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.privateKey);
    return {
      id: b64u(this.credId),
      rawId: b64u(this.credId),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
        userHandle: this.userHandle,
      },
      clientExtensionResults: {},
    };
  }
}

async function register(client: Client, key: SoftAuthenticator, token: string, username?: string) {
  const q = new URLSearchParams({ token });
  if (username) q.set('username', username);
  const opts = await client.call(`${PREFIX}/api/generate-reg-options?${q}`);
  if (opts.status !== 200) return opts;
  return client.call(`${PREFIX}/api/verify-reg`, { method: 'POST', body: key.register(opts.json, base) });
}

async function login(client: Client, key: SoftAuthenticator, next = '/') {
  const opts = await client.call(`${PREFIX}/api/generate-auth-options?next=${encodeURIComponent(next)}`);
  return client.call(`${PREFIX}/api/verify-auth`, { method: 'POST', body: key.authenticate(opts.json, base) });
}

before(async () => {
  await startUpstream();
  upstreamPort = (upstream.address() as AddressInfo).port;
  dataDir = mkdtempSync(path.join(tmpdir(), 'passkey-gate-test-'));
  db = new GateDB(dataDir);

  // Bind first to learn the port, since ORIGIN has to include it.
  const probe = http.createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const port = (probe.address() as AddressInfo).port;
  await new Promise<void>((r) => probe.close(() => r()));
  base = `http://localhost:${port}`;

  const config = loadConfig({
    ORIGIN: base,
    UPSTREAM_URL: `http://127.0.0.1:${upstreamPort}`,
    DATA_DIR: dataDir,
    APP_NAME: 'Test <App>',
    COOKIE_SECURE: 'false',
    TRUST_PROXY: '1',
    PUBLIC_PATHS: '/webhook/,/status',
    UPSTREAM_USER_HEADER: 'X-Remote-User',
  });
  gate = createGate(config, db);
  await new Promise<void>((r) => gate.server.listen(port, '127.0.0.1', r));
});

after(async () => {
  await gate.close();
  db.close();
  await new Promise<void>((r) => upstream.close(() => r()));
  rmSync(dataDir, { recursive: true, force: true });
});

// ---- tests -----------------------------------------------------------------

describe('unauthenticated', () => {
  const anon = new Client();

  test('browsers are redirected to the login page with ?next', async () => {
    const res = await anon.call('/web/index.html?x=1', { accept: 'text/html' });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), `${PREFIX}/login?next=%2Fweb%2Findex.html%3Fx%3D1`);
  });

  test('API calls get 401', async () => {
    assert.equal((await anon.call('/api/items')).status, 401);
  });

  test('login page is served with strict CSP and escaped app name', async () => {
    const res = await anon.call(`${PREFIX}/login`, { accept: 'text/html' });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-security-policy')!, /script-src 'self'/);
    assert.match(res.json, /<title>Sign in · Test &lt;App&gt;<\/title>/);
    assert.match(res.json, /name="passkey-gate-app-name" content="Test &lt;App&gt;"/);
    assert.match(res.json, /name="passkey-gate-prefix" content="\/__passkey"/);
    // Everything the CSP allows must come from files, never inline.
    assert.doesNotMatch(res.json, /<script(?![^>]*\bsrc=)[^>]*>/);
  });

  test("the login page's built assets are served with long-lived caching", async () => {
    const page = await anon.call(`${PREFIX}/login`, { accept: 'text/html' });
    const refs = [...(page.json as string).matchAll(/(?:src|href)="(\.\/assets\/[^"]+)"/g)].map((m) => m[1]!);
    assert.ok(refs.some((r) => r.endsWith('.js')), 'has a script');
    assert.ok(refs.some((r) => r.endsWith('.css')), 'has a stylesheet');
    for (const ref of refs) {
      const url = new URL(ref, `${base}${PREFIX}/login`);
      assert.ok(url.pathname.startsWith(`${PREFIX}/assets/`), url.pathname);
      const res = await anon.call(url.pathname);
      assert.equal(res.status, 200, url.pathname);
      assert.match(res.headers.get('cache-control')!, /immutable/);
    }
    assert.equal((await anon.call(`${PREFIX}/assets/missing.js`)).status, 404);
  });

  test('WebSocket upgrades are refused', async () => {
    assert.deepEqual(await anon.ws(), { ok: false, status: 401 });
  });

  test('PUBLIC_PATHS are proxied without a session', async () => {
    assert.equal((await anon.call('/webhook/abc')).status, 200);
    assert.equal((await anon.call('/status')).status, 200);
    assert.equal((await anon.call('/status/sub')).status, 200);
    assert.equal((await anon.ws('/webhook/live')).ok, true);
  });

  test('PUBLIC_PATHS fail closed on paths the upstream could normalize differently', async () => {
    // Raw http.request, not fetch: fetch would normalize these paths itself.
    const rawStatus = (rawPath: string) =>
      new Promise<number>((resolve, reject) => {
        const { port } = new URL(base);
        http
          .get({ host: '127.0.0.1', port, path: rawPath, headers: { accept: 'application/json' } }, (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          })
          .on('error', reject);
      });
    for (const p of ['/webhook/../admin', '/webhook/%2e%2e/admin', '/webhook/..%2fadmin', '/webhook\\..\\admin', '/statusx', '/WEBHOOK/a']) {
      assert.equal(await rawStatus(p), 401, p);
    }
    assert.equal(await rawStatus('/webhook/ok'), 200);
  });

  test('a client-supplied user header never reaches the upstream', async () => {
    const res = await anon.call('/webhook/x', { headers: { 'x-remote-user': 'admin' } });
    assert.equal(res.json.headers['x-remote-user'], undefined);
  });

  test('cross-origin POSTs are refused', async () => {
    const res = await anon.call(`${PREFIX}/api/verify-auth`, { method: 'POST', body: {}, origin: 'https://evil.example' });
    assert.equal(res.status, 403);
  });

  test('invalid invites are rejected', async () => {
    assert.deepEqual((await anon.call(`${PREFIX}/api/invite?token=nope`)).json, { valid: false });
    const res = await anon.call(`${PREFIX}/api/generate-reg-options?token=nope&username=bob`);
    assert.equal(res.status, 400);
  });

  test('unknown gate paths 404 instead of being proxied', async () => {
    assert.equal((await anon.call(`${PREFIX}/nope`)).status, 404);
  });
});

describe('registration and sign-in', () => {
  const client = new Client();
  const key = new SoftAuthenticator('localhost');

  test('invalid usernames are rejected', async () => {
    const token = db.createInvite({ ttlHours: 1 });
    assert.equal((await register(client, key, token, 'x')).status, 400);
    assert.equal((await register(client, key, token, 'bad name')).status, 400);
  });

  test('an invite registers a passkey and signs the user in', async () => {
    const token = db.createInvite({ ttlHours: 1 });
    const res = await register(client, key, token, 'alice');
    assert.equal(res.status, 200, JSON.stringify(res.json));
    // The very first account is always an admin.
    assert.deepEqual((await client.call(`${PREFIX}/api/session`)).json, {
      authenticated: true,
      username: 'alice',
      role: 'admin',
    });

    // Single use.
    assert.equal((await register(new Client(), new SoftAuthenticator('localhost'), token, 'bob')).status, 400);
  });

  test('sign-in works and only redirects to same-origin paths', async () => {
    client.cookie = '';
    const ok = await login(client, key, '/web/#/home');
    assert.equal(ok.status, 200);
    assert.equal(ok.json.redirect, '/web/#/home');

    const offsite = await login(new Client(), key, '//evil.example/x');
    assert.equal(offsite.json.redirect, '/');
  });

  test('a challenge cannot be replayed', async () => {
    const c = new Client();
    const opts = await c.call(`${PREFIX}/api/generate-auth-options`);
    const assertion = key.authenticate(opts.json, base);
    assert.equal((await c.call(`${PREFIX}/api/verify-auth`, { method: 'POST', body: assertion })).status, 200);
    c.cookie = '';
    const replay = await c.call(`${PREFIX}/api/verify-auth`, { method: 'POST', body: assertion });
    assert.equal(replay.status, 400);
  });

  test('a signature-counter regression is rejected', async () => {
    const saved = key.counter;
    key.counter = 0;
    assert.equal((await login(new Client(), key)).status, 400);
    key.counter = saved;
  });

  test('authenticated requests are proxied with clean forwarding headers', async () => {
    const res = await client.call('/Items?x=1', { headers: { 'x-remote-user': 'admin', cookie: `${client.cookie}; app=1` } });
    assert.equal(res.status, 200);
    assert.equal(res.json.url, '/Items?x=1');
    assert.equal(res.json.headers['x-forwarded-for'], '203.0.113.7');
    assert.equal(res.json.headers['x-forwarded-proto'], 'https');
    assert.equal(res.json.headers['x-remote-user'], 'alice');
    assert.equal(res.json.headers.cookie, 'app=1', "the gate's own cookie is stripped");
  });

  test('authenticated WebSockets are proxied', async () => {
    const res = await client.ws('/socket', { 'x-forwarded-for': '203.0.113.7' });
    assert.ok(res.ok);
    assert.equal(res.data.headers['x-forwarded-for'], '203.0.113.7');
    assert.equal(res.data.headers['x-remote-user'], 'alice');
    assert.equal(res.data.headers.cookie, 'other=1');
  });

  test('an add-device invite excludes existing passkeys', async () => {
    const user = db.getUserByName('alice')!;
    const token = db.createInvite({ ttlHours: 1, forUserId: user.id });
    assert.deepEqual((await client.call(`${PREFIX}/api/invite?token=${token}`)).json, { valid: true, forUsername: 'alice' });
    const opts = await client.call(`${PREFIX}/api/generate-reg-options?token=${token}`);
    assert.deepEqual(opts.json.excludeCredentials.map((c: { id: string }) => c.id), [b64u(key.credId)]);

    const second = new SoftAuthenticator('localhost');
    const res = await client.call(`${PREFIX}/api/verify-reg`, { method: 'POST', body: second.register(opts.json, base) });
    assert.equal(res.status, 200);
    assert.equal(db.listUsers().find((u) => u.username === 'alice')!.passkeys, 2);
  });

  test('logout ends the session', async () => {
    const c = new Client();
    await login(c, key);
    assert.equal((await c.call('/Items')).status, 200);
    assert.equal((await c.call(`${PREFIX}/api/logout`, { method: 'POST' })).status, 200);
    c.cookie = c.cookie.replace(/=.*/, '=');
    assert.equal((await c.call('/Items')).status, 401);
  });

  test('deleting a user cuts off their open sessions immediately', async () => {
    const c = new Client();
    assert.equal((await register(c, new SoftAuthenticator('localhost'), db.createInvite({ ttlHours: 1 }), 'dave')).status, 200);
    assert.equal(db.getUserByName('dave')!.role, 'user');
    assert.equal((await c.call('/Items')).status, 200);
    db.deleteUser(db.getUserByName('dave')!.id);
    assert.equal((await c.call('/Items')).status, 401);
    assert.deepEqual(await c.ws(), { ok: false, status: 401 });
  });
});

describe('roles and the admin API', () => {
  const admin = new Client();
  const adminKey = new SoftAuthenticator('localhost');
  const member = new Client();
  const A = `${PREFIX}/api/admin`;

  before(async () => {
    const alice = db.getUserByName('alice')!;
    const token = db.createInvite({ ttlHours: 1, forUserId: alice.id });
    assert.equal((await register(admin, adminKey, token)).status, 200);
    assert.equal((await register(member, new SoftAuthenticator('localhost'), db.createInvite({ ttlHours: 1 }), 'bob')).status, 200);
  });

  test('anonymous visitors are sent to sign in, and back to the admin page after', async () => {
    const anon = new Client();
    const page = await anon.call(`${PREFIX}/admin`, { accept: 'text/html' });
    assert.equal(page.status, 302);
    assert.equal(page.headers.get('location'), `${PREFIX}/login?next=%2F__passkey%2Fadmin`);
    assert.equal((await anon.call(`${A}/users`)).status, 401);

    assert.equal((await login(new Client(), adminKey, `${PREFIX}/admin`)).json.redirect, `${PREFIX}/admin`);
    assert.equal((await login(new Client(), adminKey, `${PREFIX}/api/admin/users`)).json.redirect, '/');
  });

  test('plain users get 403 from the admin page and API', async () => {
    assert.equal((await member.call(`${PREFIX}/admin`, { accept: 'text/html' })).status, 403);
    assert.equal((await member.call(`${A}/users`)).status, 403);
    assert.equal((await member.call(`${A}/invites`, { method: 'POST', body: { role: 'admin' } })).status, 403);
  });

  test('admins get the admin page and the user list', async () => {
    const page = await admin.call(`${PREFIX}/admin`, { accept: 'text/html' });
    assert.equal(page.status, 200);
    assert.match(page.json, /<title>Users · Test &lt;App&gt;<\/title>/);
    assert.match(page.headers.get('content-security-policy')!, /script-src 'self'/);

    const { users } = (await admin.call(`${A}/users`)).json;
    assert.deepEqual(
      users.map((u: { username: string; role: string }) => [u.username, u.role]),
      [['alice', 'admin'], ['bob', 'user']],
    );
  });

  test('role changes take effect on open sessions immediately', async () => {
    const bob = db.getUserByName('bob')!;
    assert.equal((await admin.call(`${A}/users/${bob.id}/role`, { method: 'POST', body: { role: 'admin' } })).status, 200);
    assert.equal((await member.call(`${A}/users`)).status, 200);
    assert.equal((await admin.call(`${A}/users/${bob.id}/role`, { method: 'POST', body: { role: 'user' } })).status, 200);
    assert.equal((await member.call(`${A}/users`)).status, 403);
    assert.equal((await admin.call(`${A}/users/${bob.id}/role`, { method: 'POST', body: { role: 'root' } })).status, 400);
  });

  test("admins can't change or delete their own account from the UI", async () => {
    const alice = db.getUserByName('alice')!;
    assert.equal((await admin.call(`${A}/users/${alice.id}/role`, { method: 'POST', body: { role: 'user' } })).status, 400);
    assert.equal((await admin.call(`${A}/users/${alice.id}`, { method: 'DELETE' })).status, 400);
    assert.equal(db.getUserById(alice.id)!.role, 'admin');
  });

  test('the last admin can never be demoted or deleted', () => {
    const alice = db.getUserByName('alice')!;
    assert.throws(() => db.setRole(alice.id, 'user'), LastAdminError);
    assert.throws(() => db.deleteUser(alice.id), LastAdminError);
  });

  test('admin invites create accounts with the chosen role', async () => {
    // Clear leftovers from earlier tests.
    assert.equal((await admin.call(`${A}/invites`, { method: 'DELETE' })).status, 200);
    assert.deepEqual((await admin.call(`${A}/invites`)).json.invites, []);

    const res = await admin.call(`${A}/invites`, { method: 'POST', body: { role: 'admin', hours: 1 } });
    assert.equal(res.status, 200);
    const token = new URL(res.json.url).searchParams.get('invite')!;
    assert.ok(res.json.url.startsWith(`${base}${PREFIX}/login?invite=`));

    const listed = (await admin.call(`${A}/invites`)).json.invites;
    assert.equal(listed.length, 1);
    assert.equal(listed[0].role, 'admin');
    assert.notEqual(listed[0].id, token, 'only the hash is ever listed');

    assert.equal((await register(new Client(), new SoftAuthenticator('localhost'), token, 'erin')).status, 200);
    assert.equal(db.getUserByName('erin')!.role, 'admin');
    assert.equal((await admin.call(`${A}/invites`, { method: 'POST', body: { hours: 0 } })).status, 400);
  });

  test('invites can be revoked one at a time', async () => {
    const { url } = (await admin.call(`${A}/invites`, { method: 'POST', body: {} })).json;
    const token = new URL(url).searchParams.get('invite')!;
    const [invite] = (await admin.call(`${A}/invites`)).json.invites;
    assert.equal((await admin.call(`${A}/invites/${invite.id}`, { method: 'DELETE' })).status, 200);
    assert.deepEqual((await admin.call(`${PREFIX}/api/invite?token=${token}`)).json, { valid: false });
    assert.equal((await admin.call(`${A}/invites/${invite.id}`, { method: 'DELETE' })).status, 404);
  });

  test('admins can delete other users, but not cross-origin', async () => {
    const bob = db.getUserByName('bob')!;
    const evil = await admin.call(`${A}/users/${bob.id}`, { method: 'DELETE', origin: 'https://evil.example' });
    assert.equal(evil.status, 403);
    assert.equal((await admin.call(`${A}/users/${bob.id}`, { method: 'DELETE' })).status, 200);
    assert.equal((await member.call('/Items')).status, 401);
    assert.equal((await admin.call(`${A}/users/${bob.id}`, { method: 'DELETE' })).status, 404);
  });
});

describe('database migration', () => {
  test('a database from before roles gains role columns, defaulting to user', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'passkey-gate-migrate-'));
    const old = new Database(path.join(dir, 'gate.db'));
    old.exec(`
      CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                          webauthn_user_id TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
      CREATE TABLE invite_tokens (token TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                                  used INTEGER NOT NULL DEFAULT 0, used_at INTEGER,
                                  for_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE);
      INSERT INTO users (username, webauthn_user_id, created_at) VALUES ('old', 'x', 0);
    `);
    old.close();

    const migrated = new GateDB(dir);
    try {
      assert.equal(migrated.getUserByName('old')!.role, 'user');
      assert.equal(migrated.countAdmins(), 0);
      assert.ok(migrated.setRole(migrated.getUserByName('old')!.id, 'admin'));
      migrated.createInvite({ ttlHours: 1, role: 'admin' });
      assert.equal(migrated.listInvites()[0]!.role, 'admin');
    } finally {
      migrated.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('upstream down', () => {
  test('HTTP gets a 502 and WebSockets are closed; the gate survives', async () => {
    const client = new Client();
    const key = new SoftAuthenticator('localhost');
    assert.equal((await register(client, key, db.createInvite({ ttlHours: 1 }), 'carol')).status, 200);

    await new Promise<void>((r) => {
      upstream.closeAllConnections();
      upstream.close(() => r());
    });
    const res = await client.call('/Items');
    assert.equal(res.status, 502);
    assert.match(res.json, /Test <App> is unreachable/);
    assert.equal((await client.ws()).ok, false);
    assert.equal((await client.call(`${PREFIX}/health`)).status, 200);

    await new Promise<void>((r) => upstream.listen(upstreamPort, '127.0.0.1', r));
  });
});
