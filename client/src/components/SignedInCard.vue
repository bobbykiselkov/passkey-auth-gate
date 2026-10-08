<script setup lang="ts">
import PasskeyButton from './PasskeyButton.vue';

defineProps<{ username: string; appName: string; busy: boolean }>();
defineEmits<{ continue: []; logout: [] }>();
</script>

<template>
  <section>
    <p class="center">
      Signed in as <strong>{{ username }}</strong>.
    </p>
    <PasskeyButton :disabled="busy" @click="$emit('continue')">Continue to {{ appName }}</PasskeyButton>
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
</style>
