<script setup lang="ts">
export type StatusKind = 'info' | 'error' | 'ok';

defineProps<{ message: string; kind: StatusKind }>();
</script>

<template>
  <div role="status" aria-live="polite">
    <p v-if="message" class="status" :class="kind">{{ message }}</p>
  </div>
</template>

<style scoped>
.status {
  margin: 0 0 16px;
  padding: 10px 14px;
  border-radius: var(--radius);
  font-size: 0.9rem;
  background: var(--surface-2);
  overflow-wrap: anywhere;
}
.error {
  background: var(--danger-bg);
  color: var(--danger);
}
.ok {
  background: var(--ok-bg);
  color: var(--ok);
}
</style>
