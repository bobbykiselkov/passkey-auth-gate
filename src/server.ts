// Entry point: load config, open the database, start listening.

import { createGate } from './app.js';
import { ConfigError, loadConfig, loadDotEnv } from './config.js';
import { GateDB } from './db.js';

let config;
try {
  loadDotEnv();
  config = loadConfig();
} catch (err) {
  if (!(err instanceof ConfigError)) throw err;
  console.error(`Configuration error: ${err.message} (see .env.example)`);
  process.exit(1);
}

if (config.cookieSecure && config.trustProxy === 0 && config.origin.startsWith('https:')) {
  console.warn(
    'Warning: TRUST_PROXY=0 with a Secure cookie — unless this process terminates TLS itself, ' +
      "it can't tell requests arrived over HTTPS and sign-in cookies won't be set.",
  );
}

const db = new GateDB(config.dataDir);
const gate = createGate(config, db);

gate.server.listen(config.port, config.host, () => {
  console.log(
    `passkey-gate listening on ${config.host ?? ''}:${config.port} → ${config.upstreamUrl} ` +
      `(origin ${config.origin}, rpID ${config.rpID}, gate paths under ${config.prefix})`,
  );
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    setTimeout(() => process.exit(0), 5000).unref();
    void gate.close().then(() => {
      db.close();
      process.exit(0);
    });
  });
}
