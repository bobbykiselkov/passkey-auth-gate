<script setup lang="ts">
import { ref } from 'vue';

import { type AdminUser, formatDate } from '../lib/admin';
import type { Role } from '../lib/passkey';

defineProps<{ users: AdminUser[]; me: string; disabled: boolean }>();
const emit = defineEmits<{ role: [user: AdminUser, role: Role]; delete: [user: AdminUser]; addDevice: [user: AdminUser] }>();

/** Row awaiting a second click to confirm deletion. */
const confirming = ref<number | null>(null);

function onDelete(user: AdminUser) {
  confirming.value = null;
  emit('delete', user);
}
</script>

<template>
  <div class="scroll">
    <table>
      <thead>
        <tr>
          <th>User</th>
          <th>Role</th>
          <th class="num">Passkeys</th>
          <th>Created</th>
          <th>Last sign-in</th>
          <th><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="user in users" :key="user.id">
          <td>
            <strong>{{ user.username }}</strong>
            <span v-if="user.username === me" class="muted"> (you)</span>
          </td>
          <td>
            <select
              :value="user.role"
              :disabled="disabled || user.username === me"
              :aria-label="`Role for ${user.username}`"
              @change="emit('role', user, ($event.target as HTMLSelectElement).value as Role)"
            >
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </td>
          <td class="num">{{ user.passkeys }}</td>
          <td class="muted">{{ formatDate(user.created_at) }}</td>
          <td class="muted">{{ formatDate(user.last_used_at) }}</td>
          <td class="actions">
            <template v-if="confirming === user.id">
              <button type="button" class="danger" :disabled="disabled" @click="onDelete(user)">Confirm delete</button>
              <button type="button" @click="confirming = null">Cancel</button>
            </template>
            <template v-else>
              <button
                type="button"
                :disabled="disabled"
                title="Create a link that adds a passkey to this account"
                @click="emit('addDevice', user)"
              >
                Device link
              </button>
              <button
                v-if="user.username !== me"
                type="button"
                class="danger"
                :disabled="disabled"
                @click="confirming = user.id"
              >
                Delete
              </button>
            </template>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.scroll {
  overflow-x: auto;
  margin: 0 -4px;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}
th,
td {
  padding: 10px 8px;
  text-align: left;
  white-space: nowrap;
  border-bottom: 1px solid var(--border);
}
th {
  color: var(--muted);
  font-weight: 500;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
tbody tr:last-child td {
  border-bottom: 0;
}
.num {
  text-align: right;
}
.actions {
  text-align: right;
}
.actions button + button {
  margin-left: 6px;
}
select,
button {
  padding: 6px 10px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--input-bg);
  color: var(--text);
  font: inherit;
  font-size: 0.85rem;
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
.danger {
  color: var(--danger);
}
.danger:hover:not(:disabled) {
  background: var(--danger-bg);
}
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip-path: inset(50%);
}
</style>
