// Values the server writes into index.html at startup (see the
// {{PREFIX}} / {{APP_NAME}} placeholders), so one build serves any app.

function meta(name: string): string {
  return document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`)?.content ?? '';
}

export const prefix = meta('passkey-gate-prefix');
export const appName = meta('passkey-gate-app-name') || 'Protected app';
