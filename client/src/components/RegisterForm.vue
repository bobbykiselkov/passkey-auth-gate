<script setup lang="ts">
import { ref, useTemplateRef } from 'vue';

import { USERNAME_HINT, USERNAME_PATTERN, USERNAME_RE } from '../lib/passkey';
import PasskeyButton from './PasskeyButton.vue';

const props = defineProps<{
  /** Set when the invite adds a device to an existing account. */
  forUsername: string | null;
  busy: boolean;
  disabled: boolean;
}>();
const emit = defineEmits<{ submit: [username: string | null]; invalid: [message: string] }>();

const username = ref('');
const input = useTemplateRef<HTMLInputElement>('input');

function onSubmit() {
  if (props.forUsername) return emit('submit', null);
  const value = username.value.trim();
  if (!USERNAME_RE.test(value)) {
    input.value?.focus();
    return emit('invalid', USERNAME_HINT);
  }
  emit('submit', value);
}

defineExpose({ focus: () => input.value?.focus() });
</script>

<template>
  <section>
    <div class="divider"><span>Invitation</span></div>
    <form novalidate @submit.prevent="onSubmit">
      <p v-if="forUsername" class="muted hint">
        Add a passkey on this device to the account “{{ forUsername }}”.
      </p>
      <template v-else>
        <p class="muted hint">You've been invited. Pick a username, then save a passkey on this device.</p>
        <label>
          Choose a username
          <input
            ref="input"
            v-model="username"
            name="username"
            autocomplete="username webauthn"
            autocapitalize="none"
            spellcheck="false"
            minlength="2"
            maxlength="32"
            :pattern="USERNAME_PATTERN"
            required
          />
        </label>
      </template>
      <PasskeyButton type="submit" variant="secondary" :busy="busy" :disabled="disabled">
        Register Passkey
      </PasskeyButton>
    </form>
  </section>
</template>

<style scoped>
.hint {
  margin: 0 0 12px;
}
label {
  display: block;
  margin-bottom: 14px;
  font-size: 0.9rem;
  color: var(--muted);
}
input {
  display: block;
  width: 100%;
  margin-top: 6px;
  padding: 12px 14px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--input-bg);
  color: var(--text);
  font: inherit;
}
.divider {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 24px 0 16px;
  color: var(--muted);
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.divider::before,
.divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--border);
}
</style>
