// The gate itself: passkey sign-in + an authenticated reverse proxy. Every
// request and WebSocket upgrade needs a signed session cookie from a
// successful passkey sign-in, except the gate's own pages (under
// GATE_PREFIX) and any PUBLIC_PATHS. Browsers without one are sent to the
// login page, everything else gets a 401.

import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { Socket } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import express, { type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import { createProxyMiddleware } from 'http-proxy-middleware';

import type { GateConfig } from './config.js';
import { type GateDB, InviteError, SqliteSessionStore, type User, hashToken } from './db.js';

interface PendingChallenge {
  challenge: string;
  expires: number;
}

declare module 'express-session' {
  interface SessionData {
    userId: number;
    authAt: number;
    auth: PendingChallenge & { next: string };
    reg: PendingChallenge & {
      inviteHash: string;
      forUserId: number | null;
      username: string;
      webauthnUserId: string;
    };
  }
}

const ROOT = fileURLToPath(new URL('..', import.meta.url));
/** The Vue login page, built by Vite (`npm run build`). */
const CLIENT_DIR = path.join(ROOT, 'dist/public');
const CHALLENGE_TTL_MS = 5 * 60_000;
const USERNAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{1,31}$/;

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

const stripV4Mapped = (ip: string | undefined) => (ip?.startsWith('::ffff:') ? ip.slice(7) : ip);

function loadSessionSecret(config: GateConfig): string {
  if (config.sessionSecret) return config.sessionSecret;
  // Generated once and kept next to the database, so sessions survive
  // restarts without anyone having to set SESSION_SECRET.
  const file = path.join(config.dataDir, 'session-secret');
  if (!existsSync(file)) writeFileSync(file, randomBytes(48).toString('hex'), { mode: 0o600 });
  return readFileSync(file, 'utf8').trim();
}

export interface Gate {
  server: http.Server;
  close(): Promise<void>;
}

export function createGate(config: GateConfig, db: GateDB): Gate {
  const P = config.prefix;
  const log = (msg: string) => console.log(msg);

  // ---- helpers -------------------------------------------------------------

  /** Real client IP: TRUST_PROXY hops back from the direct peer. */
  function clientIp(req: http.IncomingMessage): string {
    const chain = String(req.headers['x-forwarded-for'] ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    chain.push(req.socket.remoteAddress ?? '');
    return stripV4Mapped(chain[Math.max(0, chain.length - 1 - config.trustProxy)]) ?? '';
  }

  function clientProto(req: http.IncomingMessage): string {
    const forwarded = config.trustProxy > 0 ? req.headers['x-forwarded-proto'] : undefined;
    return forwarded ? String(forwarded).split(',')[0]!.trim() : 'http';
  }

  /**
   * Rewrites what the upstream sees, for plain requests and WebSocket
   * upgrades alike. X-Forwarded-For is collapsed to the single resolved
   * client IP, so the upstream only needs to trust the gate. The gate's own
   * cookie is stripped, and the user header (if configured) can only ever
   * come from the gate.
   */
  function prepareUpstreamRequest(req: http.IncomingMessage, user: User | null): void {
    const ip = clientIp(req);
    req.headers['x-forwarded-for'] = ip;
    req.headers['x-real-ip'] = ip;
    req.headers['x-forwarded-proto'] = clientProto(req);
    req.headers['x-forwarded-host'] = req.headers.host ?? new URL(config.origin).host;

    if (config.userHeader) {
      delete req.headers[config.userHeader];
      if (user) req.headers[config.userHeader] = user.username;
    }

    if (req.headers.cookie) {
      const kept = req.headers.cookie
        .split(';')
        .map((c) => c.trim())
        .filter((c) => c && !c.startsWith(`${config.cookieName}=`));
      if (kept.length) req.headers.cookie = kept.join('; ');
      else delete req.headers.cookie;
    }
  }

  /** Signed-in user, re-checked against the DB on every request so deleting
   * a user cuts off their open sessions immediately. */
  function currentUser(req: http.IncomingMessage): User | null {
    const id = (req as Request).session?.userId;
    return id ? (db.getUserById(id) ?? null) : null;
  }

  const isGatePath = (pathname: string) => pathname === P || pathname.startsWith(`${P}/`);

  /**
   * PUBLIC_PATHS match fails closed: anything the upstream might normalize
   * differently from us (dot segments, encoded slashes, backslashes) is
   * treated as not public and needs a session.
   */
  function isPublicPath(rawUrl: string | undefined): boolean {
    if (!config.publicPaths.length || !rawUrl) return false;
    const rawPath = rawUrl.split('?')[0]!;
    if (/%2f|%5c|\\/i.test(rawPath)) return false;
    let normalized: string;
    try {
      normalized = new URL(rawPath, 'http://gate.invalid').pathname;
    } catch {
      return false;
    }
    if (normalized !== rawPath || isGatePath(normalized)) return false;
    return config.publicPaths.some((p) =>
      p.endsWith('/') ? normalized.startsWith(p) : normalized === p || normalized.startsWith(`${p}/`),
    );
  }

  /** Only same-origin relative paths, so ?next= can't redirect off-site. */
  function safeNext(next: unknown): string {
    if (typeof next !== 'string' || !next.startsWith('/')) return '/';
    try {
      const url = new URL(next, config.origin);
      if (url.origin !== config.origin || isGatePath(url.pathname)) return '/';
      return url.pathname + url.search + url.hash;
    } catch {
      return '/';
    }
  }

  /** Replaces the session ID on sign-in (prevents session fixation). */
  function signIn(req: Request, userId: number): Promise<void> {
    return new Promise((resolve, reject) => {
      req.session.regenerate((err) => {
        if (err) return reject(err);
        req.session.userId = userId;
        req.session.authAt = Date.now();
        req.session.save((saveErr) => (saveErr ? reject(saveErr) : resolve()));
      });
    });
  }

  /** Takes the pending challenge out of the session (single use). */
  function takeChallenge<K extends 'auth' | 'reg'>(req: Request, kind: K) {
    const pending = req.session[kind];
    delete req.session[kind];
    if (!pending || pending.expires < Date.now()) {
      throw new HttpError(400, 'This sign-in attempt expired. Please try again.');
    }
    return pending;
  }

  // ---- app -----------------------------------------------------------------

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);

  const sessionStore = new SqliteSessionStore(db);
  const sessionMiddleware = session({
    name: config.cookieName,
    secret: loadSessionSecret(config),
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    proxy: config.trustProxy > 0,
    cookie: {
      httpOnly: true,
      secure: config.cookieSecure,
      sameSite: 'lax',
      path: '/',
      maxAge: config.sessionTtlMs,
    },
  });
  app.use(sessionMiddleware);

  // Strict headers for the gate's own pages and API — never applied to
  // proxied responses.
  function gateHeaders(req: Request, res: Response, next: NextFunction) {
    res.set({
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    });
    next();
  }

  // The built index.html is a template: the server fills in the app name
  // and prefix. Re-read when the file changes, so `vite build --watch`
  // during development needs no server restart.
  let template: { mtimeMs: number; html: string } | undefined;
  function loginHtml(): string | undefined {
    const file = path.join(CLIENT_DIR, 'index.html');
    let mtimeMs: number;
    try {
      mtimeMs = statSync(file).mtimeMs;
    } catch {
      return undefined;
    }
    if (template?.mtimeMs !== mtimeMs) {
      const html = readFileSync(file, 'utf8')
        .replaceAll('{{APP_NAME}}', escapeHtml(config.appName))
        .replaceAll('{{PREFIX}}', escapeHtml(P));
      template = { mtimeMs, html };
    }
    return template.html;
  }

  const gate = express.Router();
  gate.get('/health', (req, res) => {
    res.type('text').send('ok');
  });
  // Vite gives built assets content-hashed names, so they can be cached
  // forever. Mounted before gateHeaders, whose no-store would win otherwise.
  gate.use(
    '/assets',
    express.static(path.join(CLIENT_DIR, 'assets'), {
      index: false,
      immutable: true,
      maxAge: '1y',
      setHeaders: (res) => res.setHeader('X-Content-Type-Options', 'nosniff'),
    }),
  );
  gate.use(gateHeaders);
  gate.get('/login', (req, res) => {
    const html = loginHtml();
    if (!html) {
      return void res.status(503).type('text').send('Login page not built yet. Run `npm run build` (or `npm run dev`).');
    }
    res.type('html').send(html);
  });

  // ---- passkey API ---------------------------------------------------------

  const api = express.Router();
  api.use(
    rateLimit({
      windowMs: 15 * 60_000,
      limit: 100,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      message: { error: 'Too many attempts. Wait a few minutes and try again.' },
    }),
  );
  // WebAuthn already binds every assertion to ORIGIN, but checking Origin
  // on state-changing requests also covers logout.
  api.use((req, res, next) => {
    if (req.method !== 'GET' && req.get('origin') !== config.origin) {
      return next(new HttpError(403, 'Cross-origin request refused.'));
    }
    next();
  });
  api.use(express.json({ limit: '64kb' }));

  api.get('/session', (req, res) => {
    const user = currentUser(req);
    res.json({ authenticated: Boolean(user), username: user?.username ?? null });
  });

  api.get('/invite', (req, res) => {
    const invite = typeof req.query.token === 'string' ? db.findValidInvite(req.query.token) : undefined;
    if (!invite) return void res.json({ valid: false });
    res.json({
      valid: true,
      forUsername: invite.for_user_id ? (db.getUserById(invite.for_user_id)?.username ?? null) : null,
    });
  });

  api.get('/generate-auth-options', async (req, res) => {
    // No allowCredentials: discoverable credentials, so the browser offers
    // whichever passkeys it holds for RP_ID and no username is needed.
    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      userVerification: 'required',
    });
    req.session.auth = {
      challenge: options.challenge,
      next: safeNext(req.query.next),
      expires: Date.now() + CHALLENGE_TTL_MS,
    };
    res.json(options);
  });

  api.post('/verify-auth', async (req, res) => {
    const pending = takeChallenge(req, 'auth');
    const response = req.body as AuthenticationResponseJSON | undefined;
    if (!response || typeof response.id !== 'string') throw new HttpError(400, 'Malformed request.');

    const cred = db.getCredential(response.id);
    const user = cred && db.getUserById(cred.user_id);
    if (!cred || !user) throw new HttpError(400, "This passkey isn't registered here.");
    if (response.response?.userHandle && response.response.userHandle !== user.webauthn_user_id) {
      throw new HttpError(400, 'Invalid passkey.');
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: pending.challenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        requireUserVerification: true,
        credential: db.toWebAuthnCredential(cred),
      });
    } catch (err) {
      // Includes signature-counter regressions, i.e. a possibly cloned key.
      log(`[auth] verification failed for ${user.username} from ${clientIp(req)}: ${(err as Error).message}`);
      throw new HttpError(400, 'Invalid passkey.');
    }
    if (!verification.verified) throw new HttpError(400, 'Invalid passkey.');

    db.updateCredentialCounter(cred.id, verification.authenticationInfo.newCounter);
    await signIn(req, user.id);
    log(`[auth] ${user.username} signed in from ${clientIp(req)}`);
    res.json({ ok: true, redirect: pending.next });
  });

  api.get('/generate-reg-options', async (req, res) => {
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const invite = token ? db.findValidInvite(token) : undefined;
    if (!invite) throw new HttpError(400, 'This invite link is invalid, used, or expired.');

    let username: string;
    let webauthnUserId: string;
    let excludeCredentials: ReturnType<GateDB['getUserCredentials']> = [];
    if (invite.for_user_id) {
      const user = db.getUserById(invite.for_user_id);
      if (!user) throw new HttpError(400, 'The account this invite was for no longer exists.');
      username = user.username;
      webauthnUserId = user.webauthn_user_id;
      excludeCredentials = db.getUserCredentials(user.id);
    } else {
      username = String(req.query.username ?? '').trim();
      if (!USERNAME_RE.test(username)) {
        throw new HttpError(400, 'Username must be 2–32 characters: letters, digits, dot, dash or underscore.');
      }
      if (db.getUserByName(username)) throw new HttpError(400, 'That username is already taken.');
      webauthnUserId = randomBytes(32).toString('base64url');
    }

    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpID,
      userName: username,
      userID: Buffer.from(webauthnUserId, 'base64url'),
      attestationType: 'none',
      excludeCredentials,
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
    });
    req.session.reg = {
      challenge: options.challenge,
      inviteHash: hashToken(token),
      forUserId: invite.for_user_id,
      username,
      webauthnUserId,
      expires: Date.now() + CHALLENGE_TTL_MS,
    };
    res.json(options);
  });

  api.post('/verify-reg', async (req, res) => {
    const pending = takeChallenge(req, 'reg');
    const response = req.body as RegistrationResponseJSON | undefined;
    if (!response || typeof response.id !== 'string') throw new HttpError(400, 'Malformed request.');

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: pending.challenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        requireUserVerification: true,
      });
    } catch (err) {
      log(`[register] verification failed for ${pending.username} from ${clientIp(req)}: ${(err as Error).message}`);
      throw new HttpError(400, 'Passkey registration failed.');
    }
    if (!verification.verified) throw new HttpError(400, 'Passkey registration failed.');

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    let userId: number;
    try {
      userId = db.registerCredential({
        inviteHash: pending.inviteHash,
        forUserId: pending.forUserId,
        username: pending.username,
        webauthnUserId: pending.webauthnUserId,
        credential,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
      });
    } catch (err) {
      if (err instanceof InviteError) throw new HttpError(400, err.message);
      throw err;
    }

    await signIn(req, userId);
    log(`[register] passkey added for ${pending.username} from ${clientIp(req)}`);
    res.json({ ok: true, redirect: '/' });
  });

  api.post('/logout', (req, res, next) => {
    req.session.destroy((err) => {
      if (err) return next(err);
      res.clearCookie(config.cookieName, {
        path: '/',
        httpOnly: true,
        secure: config.cookieSecure,
        sameSite: 'lax',
      });
      res.json({ ok: true });
    });
  });

  api.use((req, res) => {
    res.status(404).json({ error: 'Not found.' });
  });
  gate.use('/api', api);
  gate.use((req, res) => {
    res.status(404).type('text').send('Not found');
  });
  app.use(P, gate);

  // ---- everything else: authenticated proxy to the upstream ----------------

  const proxy = createProxyMiddleware<Request, Response>({
    target: config.upstreamUrl,
    changeOrigin: false, // the upstream sees the public Host header
    xfwd: false, // forwarding headers come from prepareUpstreamRequest
    ws: false, // upgrades are authenticated and routed by hand below
    on: {
      error(err, req, resOrSocket) {
        console.error(`[proxy] ${req.method} ${req.url}: ${(err as NodeJS.ErrnoException).code ?? err.message}`);
        if (!resOrSocket) return;
        // A failed WebSocket upgrade just gets its socket closed.
        if (!('writeHead' in resOrSocket)) return void resOrSocket.destroy();
        // Connection errors arrive only here, not as a rejected promise,
        // so this is what answers the request when the upstream is down.
        const res = resOrSocket as Response;
        if (res.headersSent) return void res.destroy();
        res.status(502).type('text').send(`${config.appName} is unreachable right now. Try again in a moment.`);
      },
    },
  });

  app.use((req, res, next) => {
    const user = currentUser(req);
    if (user || isPublicPath(req.url)) {
      prepareUpstreamRequest(req, user);
      return proxy(req, res, next);
    }
    if ((req.method === 'GET' || req.method === 'HEAD') && req.accepts(['html', 'json']) === 'html') {
      return res.redirect(302, `${P}/login?next=${encodeURIComponent(req.originalUrl)}`);
    }
    res.status(401).set('Cache-Control', 'no-store').json({ error: 'Authentication required.' });
  });

  // Express 5 forwards rejected promises from async handlers here.
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    if (res.headersSent) {
      if (!res.writableEnded) req.socket.destroy();
      return;
    }
    if (err instanceof HttpError) return void res.status(err.status).json({ error: err.message });
    console.error(err);
    if (isGatePath(req.path)) {
      return void res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
    res.status(502).type('text').send(`${config.appName} is unreachable right now. Try again in a moment.`);
  });

  // ---- server & WebSocket upgrades -----------------------------------------

  const server = http.createServer(app);

  server.on('upgrade', (req: http.IncomingMessage, socket: Socket, head: Buffer) => {
    socket.on('error', () => socket.destroy());
    const reject = (status: number) => {
      socket.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    };
    if (isGatePath(new URL(req.url ?? '/', 'http://gate.invalid').pathname)) return reject(404);
    // express-session only needs req; the empty object stands in for res.
    sessionMiddleware(req as Request, {} as Response, (err?: unknown) => {
      if (err) return reject(500);
      const user = currentUser(req);
      if (!user && !isPublicPath(req.url)) return reject(401);
      prepareUpstreamRequest(req, user);
      proxy.upgrade(req as Request, socket, head);
    });
  });

  return {
    server,
    close: () =>
      new Promise<void>((resolve) => {
        sessionStore.stop();
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}
