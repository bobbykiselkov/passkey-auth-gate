// SQLite persistence: users, passkeys, invite tokens and sessions, all in
// one file under DATA_DIR so a single volume holds the whole instance.
// better-sqlite3 is synchronous — fine here, every query is an indexed
// lookup that takes microseconds.

import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import path from 'node:path';

import type { WebAuthnCredential } from '@simplewebauthn/server';
import Database from 'better-sqlite3';
import session from 'express-session';

export const ROLES = ['admin', 'user'] as const;
export type Role = (typeof ROLES)[number];
export const isRole = (value: unknown): value is Role => ROLES.includes(value as Role);

export interface User {
  id: number;
  username: string;
  /** WebAuthn user handle (base64url): random, never the row id or username. */
  webauthn_user_id: string;
  role: Role;
  created_at: number;
}

export interface CredentialRow {
  id: string;
  user_id: number;
  public_key: Buffer;
  counter: number;
  transports: string | null;
  device_type: string | null;
  backed_up: number;
  created_at: number;
  last_used_at: number | null;
}

export interface Invite {
  token: string;
  created_at: number;
  expires_at: number;
  used: number;
  used_at: number | null;
  for_user_id: number | null;
  /** Role of the account a new-user invite creates. */
  role: Role;
}

export interface UserSummary {
  id: number;
  username: string;
  role: Role;
  created_at: number;
  passkeys: number;
  last_used_at: number | null;
}

export class InviteError extends Error {}

/** Refused because it would leave the instance without an admin. */
export class LastAdminError extends Error {
  constructor() {
    super('There must always be at least one admin. Promote someone else first.');
  }
}

export const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex');

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    webauthn_user_id TEXT    NOT NULL UNIQUE,
    role             TEXT    NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    created_at       INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS credentials (
    id           TEXT    PRIMARY KEY,          -- credential ID, base64url
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key   BLOB    NOT NULL,             -- COSE public key bytes
    counter      INTEGER NOT NULL DEFAULT 0,
    transports   TEXT,                         -- JSON array
    device_type  TEXT,                         -- singleDevice | multiDevice
    backed_up    INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS credentials_user ON credentials(user_id);

  -- Only the SHA-256 of each token is stored: a leaked database backup
  -- doesn't hand out working invite links.
  CREATE TABLE IF NOT EXISTS invite_tokens (
    token       TEXT    PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    used_at     INTEGER,
    -- NULL: invite creates a new user. Set: adds a passkey to this user.
    for_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT    NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    sid     TEXT    PRIMARY KEY,
    sess    TEXT    NOT NULL,
    expires INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires);
`;

// Columns added after the first release. CREATE TABLE IF NOT EXISTS leaves
// existing tables alone, so older databases get them here.
const MIGRATIONS: { table: string; column: string; ddl: string }[] = [
  {
    table: 'users',
    column: 'role',
    ddl: "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user'))",
  },
  {
    table: 'invite_tokens',
    column: 'role',
    ddl: "ALTER TABLE invite_tokens ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user'))",
  },
];

export class GateDB {
  readonly db: Database.Database;
  readonly dataDir: string;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    mkdirSync(dataDir, { recursive: true });
    this.db = new Database(path.join(dataDir, 'gate.db'));
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.pragma('busy_timeout = 5000');
    this.db.exec(SCHEMA);
    for (const m of MIGRATIONS) {
      const columns = this.db.prepare<[], { name: string }>(`PRAGMA table_info(${m.table})`).all();
      if (!columns.some((c) => c.name === m.column)) this.db.exec(m.ddl);
    }
  }

  close(): void {
    this.db.close();
  }

  // ---- users & credentials -------------------------------------------------

  getUserById(id: number): User | undefined {
    return this.db.prepare<[number], User>('SELECT * FROM users WHERE id = ?').get(id);
  }

  getUserByName(username: string): User | undefined {
    return this.db.prepare<[string], User>('SELECT * FROM users WHERE username = ?').get(username);
  }

  listUsers(): UserSummary[] {
    return this.db
      .prepare<[], UserSummary>(
        `SELECT u.id, u.username, u.role, u.created_at,
                COUNT(c.id) AS passkeys, MAX(c.last_used_at) AS last_used_at
         FROM users u LEFT JOIN credentials c ON c.user_id = u.id
         GROUP BY u.id ORDER BY u.id`,
      )
      .all();
  }

  countAdmins(): number {
    return this.db.prepare<[], { n: number }>("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").get()!.n;
  }

  /** Throws LastAdminError rather than demote the only admin. */
  setRole(id: number, role: Role): boolean {
    return this.db.transaction(() => {
      const user = this.getUserById(id);
      if (!user) return false;
      if (user.role === 'admin' && role !== 'admin' && this.countAdmins() <= 1) throw new LastAdminError();
      this.db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
      return true;
    })();
  }

  /** Deletes the user, their passkeys and add-device invites (cascade) and
   * their sessions (JSON blobs, so cleared explicitly). Throws
   * LastAdminError rather than delete the only admin. */
  deleteUser(id: number): boolean {
    return this.db.transaction(() => {
      if (this.getUserById(id)?.role === 'admin' && this.countAdmins() <= 1) throw new LastAdminError();
      this.db.prepare("DELETE FROM sessions WHERE json_extract(sess, '$.userId') = ?").run(id);
      return this.db.prepare('DELETE FROM users WHERE id = ?').run(id).changes > 0;
    })();
  }

  getCredential(id: string): CredentialRow | undefined {
    return this.db.prepare<[string], CredentialRow>('SELECT * FROM credentials WHERE id = ?').get(id);
  }

  /** In the shape @simplewebauthn/server expects for verification. */
  toWebAuthnCredential(row: CredentialRow): WebAuthnCredential {
    return {
      id: row.id,
      publicKey: new Uint8Array(row.public_key),
      counter: row.counter,
      transports: row.transports ? (JSON.parse(row.transports) as string[]) : undefined,
    };
  }

  getUserCredentials(userId: number): { id: string; transports?: string[] }[] {
    return this.db
      .prepare<[number], Pick<CredentialRow, 'id' | 'transports'>>('SELECT id, transports FROM credentials WHERE user_id = ?')
      .all(userId)
      .map((c) => ({
        id: c.id,
        transports: c.transports ? (JSON.parse(c.transports) as string[]) : undefined,
      }));
  }

  updateCredentialCounter(id: string, counter: number): void {
    this.db.prepare('UPDATE credentials SET counter = ?, last_used_at = ? WHERE id = ?').run(counter, Date.now(), id);
  }

  /**
   * Atomically consumes the invite and stores the new passkey, creating the
   * user first if the invite is for a new account — with the invite's role,
   * or as admin if it's the very first account. Throws InviteError if the
   * invite was used or expired in the meantime, or the username got taken.
   */
  registerCredential(input: {
    inviteHash: string;
    forUserId: number | null;
    username: string;
    webauthnUserId: string;
    credential: WebAuthnCredential;
    deviceType: string;
    backedUp: boolean;
  }): number {
    return this.db.transaction(() => {
      const now = Date.now();
      const consumed = this.db
        .prepare('UPDATE invite_tokens SET used = 1, used_at = ? WHERE token = ? AND used = 0 AND expires_at > ?')
        .run(now, input.inviteHash, now);
      if (consumed.changes !== 1) throw new InviteError('This invite has already been used or has expired.');

      let userId = input.forUserId;
      if (userId === null) {
        if (this.getUserByName(input.username)) throw new InviteError('That username is already taken.');
        const isFirstUser = !this.db.prepare('SELECT 1 FROM users LIMIT 1').get();
        const inviteRole = this.db
          .prepare<[string], { role: Role }>('SELECT role FROM invite_tokens WHERE token = ?')
          .get(input.inviteHash)!.role;
        userId = Number(
          this.db
            .prepare('INSERT INTO users (username, webauthn_user_id, role, created_at) VALUES (?, ?, ?, ?)')
            .run(input.username, input.webauthnUserId, isFirstUser ? 'admin' : inviteRole, now).lastInsertRowid,
        );
      } else if (!this.getUserById(userId)) {
        throw new InviteError('The account this invite was for no longer exists.');
      }

      const { credential } = input;
      if (this.getCredential(credential.id)) throw new InviteError('This passkey is already registered.');
      this.db
        .prepare(
          `INSERT INTO credentials
             (id, user_id, public_key, counter, transports, device_type, backed_up, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          credential.id,
          userId,
          Buffer.from(credential.publicKey),
          credential.counter,
          JSON.stringify(credential.transports ?? []),
          input.deviceType,
          input.backedUp ? 1 : 0,
          now,
        );
      return userId;
    })();
  }

  // ---- invites -------------------------------------------------------------

  /** Returns the plaintext token — the only time it exists outside the link.
   * `role` only matters for new-user invites. */
  createInvite({
    ttlHours,
    forUserId = null,
    role = 'user',
  }: {
    ttlHours: number;
    forUserId?: number | null;
    role?: Role;
  }): string {
    const token = randomBytes(32).toString('base64url');
    const now = Date.now();
    this.db
      .prepare('INSERT INTO invite_tokens (token, created_at, expires_at, for_user_id, role) VALUES (?, ?, ?, ?, ?)')
      .run(hashToken(token), now, now + ttlHours * 3600_000, forUserId, role);
    return token;
  }

  findValidInvite(token: string): Invite | undefined {
    return this.db
      .prepare<[string, number], Invite>('SELECT * FROM invite_tokens WHERE token = ? AND used = 0 AND expires_at > ?')
      .get(hashToken(token), Date.now());
  }

  listInvites(): (Invite & { for_username: string | null })[] {
    return this.db
      .prepare<[number], Invite & { for_username: string | null }>(
        `SELECT i.*, u.username AS for_username
         FROM invite_tokens i LEFT JOIN users u ON u.id = i.for_user_id
         WHERE i.used = 0 AND i.expires_at > ? ORDER BY i.created_at`,
      )
      .all(Date.now());
  }

  /** By token hash — what listInvites() returns, never the plaintext. */
  revokeInvite(tokenHash: string): boolean {
    return (
      this.db.prepare('UPDATE invite_tokens SET used = 1, used_at = ? WHERE token = ? AND used = 0').run(Date.now(), tokenHash)
        .changes > 0
    );
  }

  revokeAllInvites(): number {
    return this.db.prepare('UPDATE invite_tokens SET used = 1, used_at = ? WHERE used = 0').run(Date.now()).changes;
  }

  prune(): void {
    const now = Date.now();
    this.db.prepare('DELETE FROM sessions WHERE expires <= ?').run(now);
    this.db.prepare('DELETE FROM invite_tokens WHERE expires_at < ?').run(now - 30 * 24 * 3600_000);
  }
}

// ---- session store ---------------------------------------------------------

// Sessions that never finish signing in only ever hold a WebAuthn
// challenge, so they're dropped server-side after this long regardless of
// the cookie's lifetime — keeps drive-by visitors from piling up rows.
const ANONYMOUS_SESSION_MS = 10 * 60_000;

type Callback = (err?: unknown) => void;

// No touch(): without it (and with resave: false) express-session only
// writes a session when its contents change, instead of on every proxied
// request. Expiry is therefore absolute (SESSION_TTL_DAYS after sign-in),
// matching the browser cookie.
export class SqliteSessionStore extends session.Store {
  readonly #gate: GateDB;
  readonly #pruneTimer: NodeJS.Timeout;

  constructor(gate: GateDB, { pruneIntervalMs = 15 * 60_000 } = {}) {
    super();
    this.#gate = gate;
    this.#pruneTimer = setInterval(() => gate.prune(), pruneIntervalMs);
    this.#pruneTimer.unref();
  }

  stop(): void {
    clearInterval(this.#pruneTimer);
  }

  #expiry(sess: session.SessionData): number {
    const cookieExpiry = sess.cookie?.expires
      ? new Date(sess.cookie.expires).getTime()
      : Date.now() + 24 * 3600_000;
    return sess.userId ? cookieExpiry : Math.min(cookieExpiry, Date.now() + ANONYMOUS_SESSION_MS);
  }

  override get(sid: string, cb: (err: unknown, session?: session.SessionData | null) => void): void {
    try {
      const row = this.#gate.db
        .prepare<[string, number], { sess: string }>('SELECT sess FROM sessions WHERE sid = ? AND expires > ?')
        .get(sid, Date.now());
      cb(null, row ? (JSON.parse(row.sess) as session.SessionData) : null);
    } catch (err) {
      cb(err);
    }
  }

  override set(sid: string, sess: session.SessionData, cb?: Callback): void {
    try {
      this.#gate.db
        .prepare(
          `INSERT INTO sessions (sid, sess, expires) VALUES (?, ?, ?)
           ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expires = excluded.expires`,
        )
        .run(sid, JSON.stringify(sess), this.#expiry(sess));
      cb?.();
    } catch (err) {
      cb?.(err);
    }
  }

  override destroy(sid: string, cb?: Callback): void {
    try {
      this.#gate.db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
      cb?.();
    } catch (err) {
      cb?.(err);
    }
  }
}
