<script setup lang="ts">
import { ref } from 'vue';

import { type AdminInvite, type CreatedInvite, formatDate } from '../lib/admin';
import type { Role } from '../lib/passkey';

defineProps<{
  invites: AdminInvite[];
  /** The link just created — shown once, since only its hash is stored. */
  created: (CreatedInvite & { label: string }) | null;
  disabled: boolean;
}>();
const emit = defineEmits<{
  create: [input: { hours: number; role: Role }];
  revoke: [invite: AdminInvite];
  revokeAll: [];
  dismiss: [];
}>();

const role = ref<Role>('user');
const hours = ref(72);
const copied = ref(false);
const linkInput = ref<HTMLInputElement | null>(null);

async function copy(url: string) {
  try {
    await navigator.clipboard.writeText(url);
    copied.value = true;
    setTimeout(() => (copied.value = false), 2000);
  } catch {
    // Clipboard blocked (e.g. plain http): select it for a manual copy.
    linkInput.value?.select();
  }
}
</script>

<template>
  <section>
    <form class="create" @submit.prevent="emit('create', { hours, role })">
      <label>
        New account role
        <select v-model="role" :disabled="disabled">
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </label>
      <label>
        Expires after
        <select v-model.number="hours" :disabled="disabled">
          <option :value="24">1 day</option>
          <option :value="72">3 days</option>
          <option :value="168">7 days</option>
          <option :value="720">30 days</option>
        </select>
      </label>
      <button type="submit" class="primary" :disabled="disabled">Create invite link</button>
    </form>

    <div v-if="created" class="created">
      <p>
        <strong>{{ created.label }}</strong>
        <span class="muted"> · single use, expires {{ formatDate(created.expiresAt) }}</span>
      </p>
      <div class="link-row">
        <input ref="linkInput" :value="created.url" readonly aria-label="Invite link" @focus="linkInput?.select()" />
        <button type="button" class="primary" @click="copy(created.url)">{{ copied ? 'Copied' : 'Copy' }}</button>
        <button type="button" @click="emit('dismiss')">Done</button>
      </div>
      <p class="muted small">
        This is the only time the link is shown. Send it over a private channel — anyone holding it can register.
      </p>
    </div>

    <template v-if="invites.length">
      <ul class="invites">
        <li v-for="invite in invites" :key="invite.id">
          <span>
            {{ invite.forUsername ? `Add a passkey to ${invite.forUsername}` : `New ${invite.role}` }}
            <span class="muted"> · expires {{ formatDate(invite.expiresAt) }}</span>
          </span>
          <button type="button" class="danger" :disabled="disabled" @click="emit('revoke', invite)">Revoke</button>
        </li>
      </ul>
      <button v-if="invites.length > 1" type="button" class="danger" :disabled="disabled" @click="emit('revokeAll')">
        Revoke all
      </button>
    </template>
    <p v-else class="muted">No open invites.</p>
  </section>
</template>

<style scoped>
.create {
  display: flex;
  flex-wrap: wrap;
  align-items: end;
  gap: 12px;
  margin-bottom: 16px;
}
label {
  display: grid;
  gap: 4px;
  font-size: 0.8rem;
  color: var(--muted);
}
select,
input,
button {
  min-height: 38px;
  padding: 6px 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--input-bg);
  color: var(--text);
  font: inherit;
  font-size: 0.9rem;
}
button {
  cursor: pointer;
}
button:hover:not(:disabled) {
  background: var(--surface-2);
}
button:disabled,
select:disabled {
  opacity: 0.55;
  cursor: default;
}
.primary {
  border-color: transparent;
  color: #fff;
  font-weight: 600;
  background: linear-gradient(135deg, var(--accent-2), var(--accent));
}
.primary:hover:not(:disabled) {
  background: linear-gradient(135deg, var(--accent-2), var(--accent));
  filter: brightness(1.1);
}
.danger {
  color: var(--danger);
}
.danger:hover:not(:disabled) {
  background: var(--danger-bg);
}
.created {
  margin-bottom: 16px;
  padding: 14px;
  border-radius: var(--radius);
  background: var(--ok-bg);
}
.created p {
  margin: 0 0 8px;
  overflow-wrap: anywhere;
}
.link-row {
  display: flex;
  gap: 8px;
}
.link-row input {
  flex: 1;
  min-width: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.8rem;
}
.small {
  margin: 8px 0 0 !important;
  font-size: 0.8rem;
}
.invites {
  list-style: none;
  margin: 0 0 12px;
  padding: 0;
}
.invites li {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 8px 0;
  border-bottom: 1px solid var(--border);
  font-size: 0.9rem;
}
@media (max-width: 520px) {
  .link-row {
    flex-wrap: wrap;
  }
  .link-row input {
    flex-basis: 100%;
  }
}
</style>
