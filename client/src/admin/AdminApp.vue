<script setup lang="ts">
import { onMounted, ref } from 'vue';

import BrandHeader from '../components/BrandHeader.vue';
import StatusBanner, { type StatusKind } from '../components/StatusBanner.vue';
import {
  type AdminInvite,
  type AdminUser,
  type CreatedInvite,
  createInvite,
  deleteUser,
  listInvites,
  listUsers,
  revokeAllInvites,
  revokeInvite,
  setRole,
} from '../lib/admin';
import { appName, prefix } from '../lib/config';
import { type Role, describeError, getSession, logout } from '../lib/passkey';
import InvitesPanel from './InvitesPanel.vue';
import UsersTable from './UsersTable.vue';

const me = ref('');
const loaded = ref(false);
const users = ref<AdminUser[]>([]);
const invites = ref<AdminInvite[]>([]);
const created = ref<(CreatedInvite & { label: string }) | null>(null);
const busy = ref(false);
const status = ref<{ message: string; kind: StatusKind }>({ message: '', kind: 'info' });

function setStatus(message: string, kind: StatusKind = 'info') {
  status.value = { message, kind };
}

async function reload() {
  [users.value, invites.value] = await Promise.all([listUsers(), listInvites()]);
}

/** Runs one change at a time, then refreshes both lists — on failure too,
 * since the server is the source of truth. */
async function run(fn: () => Promise<string | void>) {
  busy.value = true;
  setStatus('');
  try {
    const message = await fn();
    if (message) setStatus(message, 'ok');
  } catch (err) {
    setStatus(describeError(err), 'error');
  } finally {
    await reload().catch(() => {});
    busy.value = false;
  }
}

const onRole = (user: AdminUser, role: Role) =>
  run(async () => {
    await setRole(user.id, role);
    return `${user.username} is now ${role === 'admin' ? 'an admin' : 'a user'}.`;
  });

const onDelete = (user: AdminUser) =>
  run(async () => {
    await deleteUser(user.id);
    return `Deleted ${user.username}. Their passkeys no longer work and open sessions are signed out.`;
  });

const onAddDevice = (user: AdminUser) =>
  run(async () => {
    const invite = await createInvite({ hours: 72, forUserId: user.id });
    created.value = { ...invite, label: `Add a passkey to ${user.username}` };
  });

const onCreate = ({ hours, role }: { hours: number; role: Role }) =>
  run(async () => {
    const invite = await createInvite({ hours, role });
    created.value = { ...invite, label: `New ${role} account` };
  });

const onRevoke = (invite: AdminInvite) =>
  run(async () => {
    await revokeInvite(invite.id);
    return 'Invite revoked.';
  });

const onRevokeAll = () =>
  run(async () => {
    const { revoked } = await revokeAllInvites();
    return `Revoked ${revoked} invite(s).`;
  });

const onLogout = () =>
  run(async () => {
    await logout();
    location.replace(`${prefix}/login`);
  });

onMounted(async () => {
  const session = await getSession();
  // The server only serves this page to admins, but a session can end or
  // be demoted while it's open.
  if (!session.authenticated) return location.replace(`${prefix}/login?next=${encodeURIComponent(`${prefix}/admin`)}`);
  me.value = session.username ?? '';
  try {
    await reload();
    loaded.value = true;
  } catch (err) {
    setStatus(describeError(err), 'error');
  }
});
</script>

<template>
  <main class="panel">
    <div class="top">
      <BrandHeader :app-name="appName" subtitle="User management" />
      <nav>
        <span class="muted">Signed in as <strong>{{ me }}</strong></span>
        <a href="/">Back to {{ appName }}</a>
        <button type="button" :disabled="busy" @click="onLogout">Sign out</button>
      </nav>
    </div>

    <StatusBanner :message="status.message" :kind="status.kind" />

    <template v-if="loaded">
      <h2>Users <span class="muted count">{{ users.length }}</span></h2>
      <UsersTable
        :users="users"
        :me="me"
        :disabled="busy"
        @role="onRole"
        @delete="onDelete"
        @add-device="onAddDevice"
      />

      <h2>Invites</h2>
      <InvitesPanel
        :invites="invites"
        :created="created"
        :disabled="busy"
        @create="onCreate"
        @revoke="onRevoke"
        @revoke-all="onRevokeAll"
        @dismiss="created = null"
      />
    </template>
    <p v-else-if="!status.message" class="muted">Loading…</p>
  </main>
</template>

<style scoped>
.panel {
  align-self: start;
  width: 100%;
  max-width: 900px;
  margin: 24px 0;
  padding: 28px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  box-shadow: 0 20px 60px rgb(0 0 0 / 0.45);
}
.top {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}
.top :deep(.brand) {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px 12px;
  text-align: left;
}
.top :deep(.brand h1) {
  margin: 0;
}
.top :deep(.brand p) {
  flex-basis: 100%;
  margin: 0;
}
nav {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  font-size: 0.9rem;
}
nav a {
  color: var(--accent);
}
nav button {
  padding: 6px 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text);
  font: inherit;
  cursor: pointer;
}
nav button:hover:not(:disabled) {
  background: var(--surface-2);
}
h2 {
  margin: 28px 0 12px;
  font-size: 1.1rem;
  font-weight: 600;
}
.count {
  font-weight: 400;
}
@media (max-width: 520px) {
  .panel {
    margin: 0;
    padding: 20px 16px;
  }
}
</style>
