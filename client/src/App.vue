<script setup lang="ts">
import { browserSupportsWebAuthn } from '@simplewebauthn/browser';
import { computed, nextTick, onMounted, ref, useTemplateRef } from 'vue';

import BrandHeader from './components/BrandHeader.vue';
import PasskeyButton from './components/PasskeyButton.vue';
import RegisterForm from './components/RegisterForm.vue';
import SignedInCard from './components/SignedInCard.vue';
import StatusBanner, { type StatusKind } from './components/StatusBanner.vue';
import { appName, prefix } from './lib/config';
import { type InviteInfo, describeError, getInvite, getSession, go, logout, register, signIn } from './lib/passkey';

type Phase = 'loading' | 'unsupported' | 'signed-in' | 'sign-in';
type Action = 'auth' | 'reg' | 'logout';

const params = new URLSearchParams(location.search);
const inviteToken = params.get('invite');
const next = params.get('next') || '/';

const phase = ref<Phase>('loading');
const username = ref('');
const isAdmin = ref(false);
const invite = ref<InviteInfo | null>(null);
const busy = ref<Action | null>(null);
const status = ref<{ message: string; kind: StatusKind }>({ message: '', kind: 'info' });
const registerForm = useTemplateRef<InstanceType<typeof RegisterForm>>('registerForm');

const showRegister = computed(() => phase.value === 'sign-in' && invite.value?.valid === true);

function setStatus(message: string, kind: StatusKind = 'info') {
  status.value = { message, kind };
}

/** Runs one action at a time, surfacing any failure in the status banner. */
async function run(action: Action, fn: () => Promise<void>) {
  busy.value = action;
  setStatus('');
  try {
    await fn();
  } catch (err) {
    setStatus(describeError(err), 'error');
    busy.value = null;
  }
}

const onSignIn = () =>
  run('auth', async () => {
    const redirect = await signIn(next);
    setStatus('Signed in. Loading…', 'ok');
    go(redirect);
  });

const onRegister = (name: string | null) =>
  run('reg', async () => {
    const redirect = await register(inviteToken!, name);
    setStatus('Passkey registered. Loading…', 'ok');
    // Drop the spent invite from history before leaving.
    history.replaceState(null, '', `${prefix}/login`);
    go(redirect);
  });

const onLogout = () =>
  run('logout', async () => {
    await logout();
    location.replace(`${prefix}/login`);
  });

onMounted(async () => {
  if (!browserSupportsWebAuthn()) {
    phase.value = 'unsupported';
    setStatus("This browser doesn't support passkeys. Try an up-to-date Chrome, Safari, Firefox or Edge.", 'error');
    return;
  }

  const session = await getSession();
  if (session.authenticated && !inviteToken) {
    username.value = session.username ?? '';
    isAdmin.value = session.role === 'admin';
    phase.value = 'signed-in';
    return;
  }

  phase.value = 'sign-in';
  if (!inviteToken) return;
  try {
    invite.value = await getInvite(inviteToken);
    if (!invite.value.valid) {
      setStatus('This invite link is invalid, already used, or expired. Ask for a new one.', 'error');
    } else if (!invite.value.forUsername) {
      await nextTick();
      registerForm.value?.focus();
    }
  } catch (err) {
    setStatus(describeError(err), 'error');
  }
});
</script>

<template>
  <main class="card">
    <BrandHeader :app-name="appName" />
    <StatusBanner :message="status.message" :kind="status.kind" />

    <p v-if="phase === 'loading'" class="muted center">Loading…</p>

    <SignedInCard
      v-else-if="phase === 'signed-in'"
      :username="username"
      :app-name="appName"
      :is-admin="isAdmin"
      :busy="busy === 'logout'"
      @continue="go(next)"
      @logout="onLogout"
    />

    <template v-else-if="phase === 'sign-in'">
      <PasskeyButton :busy="busy === 'auth'" :disabled="busy !== null" @click="onSignIn">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path
            d="M8 12a4 4 0 1 1 0-8 4 4 0 0 1 0 8Zm0 2c3 0 7 1.5 7 4v2H1v-2c0-2.5 4-4 7-4Zm11.5-6a3.5 3.5 0 0 1 1 6.86V17l1.5 1.5-1.5 1.5 1.5 1.5L20 23l-2-2v-6.14A3.5 3.5 0 0 1 19.5 8Zm0 2a1 1 0 1 0 0 2 1 1 0 0 0 0-2Z"
          />
        </svg>
        Sign in with Passkey
      </PasskeyButton>

      <RegisterForm
        v-if="showRegister"
        ref="registerForm"
        :for-username="invite?.forUsername ?? null"
        :busy="busy === 'reg'"
        :disabled="busy !== null"
        @submit="onRegister"
        @invalid="(msg) => setStatus(msg, 'error')"
      />
    </template>
  </main>
</template>

<style scoped>
.card {
  width: 100%;
  max-width: 380px;
  padding: 32px 28px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  box-shadow: 0 20px 60px rgb(0 0 0 / 0.45);
}
.center {
  text-align: center;
}
</style>
