// Configuration from environment variables. Everything app-specific
// (domain, upstream, branding, which paths stay public) lives here, so one
// image can front any web app.

import { existsSync } from 'node:fs';
import path from 'node:path';

export interface GateConfig {
  /** Port the gate listens on. */
  port: number;
  /** Listen address; undefined = all interfaces. */
  host: string | undefined;
  /** Exact public origin, e.g. https://media.example.com (no trailing slash). */
  origin: string;
  /** WebAuthn relying-party ID: ORIGIN's hostname or a parent domain of it. */
  rpID: string;
  /** Name shown in the browser's passkey prompt. */
  rpName: string;
  /** Name shown on the login page. */
  appName: string;
  /** Where to proxy authenticated traffic, e.g. http://app:8080. */
  upstreamUrl: string;
  /** Directory for gate.db and the generated session secret. */
  dataDir: string;
  /** Signs session cookies; generated into dataDir when undefined. */
  sessionSecret: string | undefined;
  sessionTtlMs: number;
  inviteTtlHours: number;
  /** Reverse-proxy hops in front of the gate (see README). */
  trustProxy: number;
  cookieSecure: boolean;
  cookieName: string;
  /** Path prefix for everything the gate serves itself. */
  prefix: string;
  /** Path prefixes proxied without authentication (e.g. webhooks). */
  publicPaths: string[];
  /** If set, the signed-in username is sent upstream in this header. */
  userHeader: string | undefined;
}

export class ConfigError extends Error {}

/**
 * Loads ./.env (or ENV_FILE) into process.env if it exists, for running
 * from source. Variables already set in the environment win, so Docker /
 * systemd configuration is never overridden by a stray file.
 */
export function loadDotEnv(): void {
  const file = path.resolve(process.env.ENV_FILE || '.env');
  if (existsSync(file)) process.loadEnvFile(file);
  else if (process.env.ENV_FILE) throw new ConfigError(`ENV_FILE not found: ${file}`);
}

type Env = Record<string, string | undefined>;

const PREFIX_RE = /^(\/[A-Za-z0-9._~-]+)+$/;
const HEADER_RE = /^[A-Za-z0-9-]+$/;

function req(env: Env, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new ConfigError(`Missing required environment variable ${name}`);
  return value;
}

function num(env: Env, name: string, fallback: number, { min = 0 } = {}): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < min) {
    throw new ConfigError(`${name} must be a number >= ${min} (got "${raw}")`);
  }
  return value;
}

function parseOrigin(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError(`ORIGIN is not a valid URL: ${raw}`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ConfigError('ORIGIN must start with https:// (or http:// for localhost testing)');
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new ConfigError('ORIGIN must be scheme + host (+ port) only, without a path');
  }
  return url.origin;
}

/** The single-use registration link for an invite token. */
export const inviteUrl = (config: { origin: string; prefix: string }, token: string) =>
  `${config.origin}${config.prefix}/login?invite=${token}`;

/** The subset the admin CLI needs; no upstream required. */
export function loadCliConfig(env: Env = process.env) {
  const origin = parseOrigin(env.ORIGIN?.trim() || 'http://localhost:3000');
  const prefix = (env.GATE_PREFIX?.trim() || '/__passkey').replace(/\/+$/, '');
  if (!PREFIX_RE.test(prefix)) throw new ConfigError(`GATE_PREFIX is not a valid path: ${prefix}`);
  return {
    origin,
    prefix,
    dataDir: path.resolve(env.DATA_DIR?.trim() || './data'),
    inviteTtlHours: num(env, 'INVITE_TTL_HOURS', 72, { min: 0.01 }),
  };
}

export function loadConfig(env: Env = process.env): GateConfig {
  const origin = parseOrigin(req(env, 'ORIGIN'));
  const originHost = new URL(origin).hostname;
  const rpID = env.RP_ID?.trim() || originHost;
  if (originHost !== rpID && !originHost.endsWith(`.${rpID}`)) {
    throw new ConfigError(`RP_ID (${rpID}) must equal ORIGIN's hostname (${originHost}) or a parent domain of it`);
  }

  const upstreamUrl = req(env, 'UPSTREAM_URL');
  try {
    new URL(upstreamUrl);
  } catch {
    throw new ConfigError(`UPSTREAM_URL is not a valid URL: ${upstreamUrl}`);
  }

  const sessionSecret = env.SESSION_SECRET?.trim() || undefined;
  if (sessionSecret && sessionSecret.length < 32) {
    throw new ConfigError('SESSION_SECRET must be at least 32 characters (try: openssl rand -hex 32)');
  }

  const cookieSecure = env.COOKIE_SECURE?.trim() !== 'false';
  const { prefix, dataDir, inviteTtlHours } = loadCliConfig(env);

  const publicPaths = (env.PUBLIC_PATHS ?? '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  for (const p of publicPaths) {
    if (!p.startsWith('/')) throw new ConfigError(`PUBLIC_PATHS entries must start with "/": ${p}`);
    if (p === '/') throw new ConfigError('PUBLIC_PATHS must not contain "/" — that would disable the gate');
  }

  const userHeader = env.UPSTREAM_USER_HEADER?.trim().toLowerCase() || undefined;
  if (userHeader && !HEADER_RE.test(userHeader)) {
    throw new ConfigError(`UPSTREAM_USER_HEADER is not a valid header name: ${userHeader}`);
  }

  const appName = env.APP_NAME?.trim() || 'Protected app';

  return {
    port: num(env, 'PORT', 3000, { min: 1 }),
    host: env.HOST?.trim() || undefined,
    origin,
    rpID,
    rpName: env.RP_NAME?.trim() || appName,
    appName,
    upstreamUrl,
    dataDir,
    sessionSecret,
    sessionTtlMs: num(env, 'SESSION_TTL_DAYS', 30, { min: 0.001 }) * 24 * 3600_000,
    inviteTtlHours,
    trustProxy: num(env, 'TRUST_PROXY', 1),
    cookieSecure,
    // __Host- pins the cookie to this exact host, HTTPS and path "/".
    cookieName: env.COOKIE_NAME?.trim() || (cookieSecure ? '__Host-passkey-gate' : 'passkey-gate'),
    prefix,
    publicPaths,
    userHeader,
  };
}
