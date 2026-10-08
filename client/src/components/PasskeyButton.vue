<script setup lang="ts">
withDefaults(
  defineProps<{
    variant?: 'primary' | 'secondary';
    type?: 'button' | 'submit';
    /** Shows busyLabel instead of the slot while true. */
    busy?: boolean;
    busyLabel?: string;
    disabled?: boolean;
  }>(),
  { variant: 'primary', type: 'button', busy: false, busyLabel: 'Waiting for passkey…', disabled: false },
);
defineEmits<{ click: [] }>();
</script>

<template>
  <button :type="type" :class="variant" :disabled="disabled || busy" :aria-busy="busy" @click="$emit('click')">
    <template v-if="busy">{{ busyLabel }}</template>
    <slot v-else />
  </button>
</template>

<style scoped>
button {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  width: 100%;
  min-height: 48px;
  padding: 12px 16px;
  border-radius: var(--radius);
  border: 1px solid transparent;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
  transition: filter 0.15s, background 0.15s, opacity 0.15s;
}
button + button {
  margin-top: 10px;
}
button:disabled {
  opacity: 0.55;
  cursor: progress;
}
button :deep(svg) {
  width: 20px;
  height: 20px;
  fill: currentColor;
}
.primary {
  color: #fff;
  background: linear-gradient(135deg, var(--accent-2), var(--accent));
}
.primary:hover:not(:disabled) {
  filter: brightness(1.1);
}
.secondary {
  color: var(--text);
  background: transparent;
  border-color: var(--border);
}
.secondary:hover:not(:disabled) {
  background: var(--surface-2);
}
</style>
