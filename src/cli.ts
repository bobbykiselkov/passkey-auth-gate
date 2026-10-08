// Admin CLI — invites and users. Inside the container it's on PATH:
//
//   docker exec -it passkey-gate passkey-gate invite
//   docker exec -it passkey-gate passkey-gate invite --user alice --hours 24
//   docker exec -it passkey-gate passkey-gate users

import { parseArgs } from 'node:util';

import { ConfigError, loadCliConfig, loadDotEnv } from './config.js';
import { GateDB } from './db.js';

const USAGE = `Usage: passkey-gate <command>

  invite [--hours N] [--user NAME]
      Print a single-use registration link (valid INVITE_TTL_HOURS, default 72).
      With --user, the link adds another passkey to an existing account
      (new device, lost phone) instead of creating a new one.
  invites           List unused, unexpired invites
  revoke-invites    Invalidate every unused invite
  users             List users and their passkeys
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
    help: { type: 'boolean', short: 'h' },
  },
});
const [command, arg] = positionals;
const db = new GateDB(config.dataDir);

switch (values.help ? 'help' : command) {
  case 'invite': {
    const ttlHours = values.hours === undefined ? config.inviteTtlHours : Number(values.hours);
    if (!(ttlHours > 0)) fail('--hours must be a positive number');
    let forUserId: number | null = null;
    if (values.user) {
      const user = db.getUserByName(values.user);
      if (!user) fail(`No user named "${values.user}"`);
      forUserId = user.id;
    }
    const token = db.createInvite({ ttlHours, forUserId });
    console.log(`${config.origin}${config.prefix}/login?invite=${token}`);
    console.error(
      `\nSingle use, expires in ${ttlHours}h` +
        (values.user ? `, adds a passkey to "${values.user}".` : ', creates a new user.') +
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
        for: i.for_username ?? '(new user)',
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
        passkeys: u.passkeys,
        created: fmt(u.created_at),
        'last sign-in': fmt(u.last_used_at),
      })),
    );
    break;
  }

  case 'delete-user': {
    if (!arg) fail('Usage: passkey-gate delete-user NAME');
    const user = db.getUserByName(arg);
    if (!user) fail(`No user named "${arg}"`);
    db.deleteUser(user.id);
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
