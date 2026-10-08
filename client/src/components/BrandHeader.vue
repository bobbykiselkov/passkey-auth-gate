<script setup lang="ts">
defineProps<{ appName: string }>();
</script>

<template>
  <header class="brand">
    <svg class="logo" viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm-3 8V7a3 3 0 1 1 6 0v3H9Zm3 4a2 2 0 0 1 1 3.73V19h-2v-1.27A2 2 0 0 1 12 14Z"
      />
    </svg>
    <h1>{{ appName }}</h1>
    <p class="muted">Private — passkey required</p>
  </header>
</template>

<style scoped>
.brand {
  text-align: center;
  margin-bottom: 24px;
}
.logo {
  width: 44px;
  height: 44px;
  padding: 10px;
  border-radius: 12px;
  fill: #fff;
  background: linear-gradient(135deg, var(--accent-2), var(--accent));
}
h1 {
  margin: 12px 0 2px;
  font-size: 1.5rem;
  font-weight: 650;
  letter-spacing: -0.01em;
  overflow-wrap: anywhere;
}
</style>
