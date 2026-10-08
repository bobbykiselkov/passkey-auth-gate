# Build stage: compile TypeScript, then drop dev dependencies. The compiler
# toolchain is only needed if better-sqlite3 has no prebuilt binary for the
# target platform, and it stays out of the final image either way.
FROM node:24-bookworm-slim AS build
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig*.json vite.config.ts ./
COPY src ./src
COPY client ./client
# Server → dist/*.js, Vue login page → dist/public (Vite).
RUN npm run build && npm prune --omit=dev

FROM node:24-bookworm-slim
ENV NODE_ENV=production \
    DATA_DIR=/data \
    PORT=3000
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
# `docker exec <container> passkey-gate invite` etc.
RUN printf '#!/bin/sh\nexec node /app/dist/cli.js "$@"\n' > /usr/local/bin/passkey-gate \
 && chmod +x /usr/local/bin/passkey-gate \
 && mkdir -p /data && chown node:node /data
# Compose can override the uid/gid with `user:` to match a bind mount's
# owner; this default just keeps it non-root either way.
USER node
VOLUME /data
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+(process.env.GATE_PREFIX||'/__passkey')+'/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/server.js"]
