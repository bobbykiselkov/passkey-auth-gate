<script setup lang="ts">
import PasskeyButton from './PasskeyButton.vue';

import { prefix } from '../lib/config';

defineProps<{ username: string; appName: string; isAdmin: boolean; busy: boolean }>();
defineEmits<{ continue: []; logout: [] }>();
</script>

<template>
  <section>
    <p class="center">
      Signed in as <strong>{{ username }}</strong>.
    </p>
    <PasskeyButton :disabled="busy" @click="$emit('continue')">Continue to {{ appName }}</PasskeyButton>
    <a v-if="isAdmin" class="admin-link" :href="`${prefix}/admin`">Manage users</a>
    <PasskeyButton variant="secondary" :busy="busy" busy-label="Signing out…" @click="$emit('logout')">
      Sign out
    </PasskeyButton>
  </section>
</template>

<style scoped>
.center {
  margin: 0 0 16px;
  text-align: center;
}
.admin-link {
  display: block;
  margin-top: 10px;
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text);
  font-weight: 600;
  text-align: center;
  text-decoration: none;
}
.admin-link:hover {
  background: var(--surface-2);
}
.admin-link + button {
  margin-top: 10px;
}
</style>
