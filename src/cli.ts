// Admin CLI — invites and users. Inside the container it's on PATH:
//
//   docker exec -it passkey-gate passkey-gate invite
//   docker exec -it passkey-gate passkey-gate invite --user alice --hours 24
//   docker exec -it passkey-gate passkey-gate users
//   docker exec -it passkey-gate passkey-gate set-role alice admin

import { parseArgs } from 'node:util';

import { ConfigError, inviteUrl, loadCliConfig, loadDotEnv } from './config.js';
import { GateDB, LastAdminError, ROLES, isRole } from './db.js';

const USAGE = `Usage: passkey-gate <command>

  invite [--hours N] [--user NAME] [--role admin|user]
      Print a single-use registration link (valid INVITE_TTL_HOURS, default 72).
      With --user, the link adds another passkey to an existing account
      (new device, lost phone) instead of creating a new one. --role sets the
      new account's role (default user; the very first account is always admin).
  invites           List unused, unexpired invites
  revoke-invites    Invalidate every unused invite
  users             List users, their roles and passkeys
  set-role NAME ROLE
      Make a user an admin (can manage users at GATE_PREFIX/admin) or a user
  delete-user NAME  Delete a user, their passkeys and their sessions`;

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

const fmt = (ms: number | null) => (ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 16) : '—');

let config;
try {
  loadDotEnv();
  config = loadCliConfig();
} catch (err) {
  if (err instanceof ConfigError) fail(`Configuration error: ${err.message}`);
  throw err;
}

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    hours: { type: 'string' },
    user: { type: 'string' },
    role: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
  },
});
const [command, arg, arg2] = positionals;
const db = new GateDB(config.dataDir);

switch (values.help ? 'help' : command) {
  case 'invite': {
    const ttlHours = values.hours === undefined ? config.inviteTtlHours : Number(values.hours);
    if (!(ttlHours > 0)) fail('--hours must be a positive number');
    const role = values.role ?? 'user';
    if (!isRole(role)) fail(`--role must be one of: ${ROLES.join(', ')}`);
    if (values.user && values.role) fail('--role only applies to new users; use set-role for existing ones');
    let forUserId: number | null = null;
    if (values.user) {
      const user = db.getUserByName(values.user);
      if (!user) fail(`No user named "${values.user}"`);
      forUserId = user.id;
    }
    const token = db.createInvite({ ttlHours, forUserId, role });
    console.log(inviteUrl(config, token));
    console.error(
      `\nSingle use, expires in ${ttlHours}h` +
        (values.user ? `, adds a passkey to "${values.user}".` : `, creates a new ${role === 'admin' ? 'admin' : 'user'}.`) +
        '\nSend it over a private channel — anyone holding it can register.',
    );
    break;
  }

  case 'invites': {
    const invites = db.listInvites();
    if (!invites.length) {
      console.log('No open invites.');
      break;
    }
    console.table(
      invites.map((i) => ({
        created: fmt(i.created_at),
        expires: fmt(i.expires_at),
        for: i.for_username ?? `(new ${i.role})`,
      })),
    );
    break;
  }

  case 'revoke-invites':
    console.log(`Revoked ${db.revokeAllInvites()} invite(s).`);
    break;

  case 'users': {
    const users = db.listUsers();
    if (!users.length) {
      console.log('No users yet — create an invite with: passkey-gate invite');
      break;
    }
    console.table(
      users.map((u) => ({
        username: u.username,
        role: u.role,
        passkeys: u.passkeys,
        created: fmt(u.created_at),
        'last sign-in': fmt(u.last_used_at),
      })),
    );
    break;
  }

  case 'set-role': {
    if (!arg || !isRole(arg2)) fail(`Usage: passkey-gate set-role NAME ${ROLES.join('|')}`);
    const user = db.getUserByName(arg);
    if (!user) fail(`No user named "${arg}"`);
    try {
      db.setRole(user.id, arg2);
    } catch (err) {
      if (err instanceof LastAdminError) fail(err.message);
      throw err;
    }
    console.log(`"${user.username}" is now ${arg2 === 'admin' ? 'an admin' : 'a user'}.`);
    break;
  }

  case 'delete-user': {
    if (!arg) fail('Usage: passkey-gate delete-user NAME');
    const user = db.getUserByName(arg);
    if (!user) fail(`No user named "${arg}"`);
    try {
      db.deleteUser(user.id);
    } catch (err) {
      if (err instanceof LastAdminError) fail(err.message);
      throw err;
    }
    console.log(`Deleted "${user.username}" — their passkeys no longer work and open sessions are signed out.`);
    break;
  }

  case 'help':
    console.log(USAGE);
    break;

  default:
    fail(USAGE);
}

db.close();
