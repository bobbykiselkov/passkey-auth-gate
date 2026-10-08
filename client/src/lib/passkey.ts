// The two WebAuthn ceremonies plus session calls, kept out of the
// components so they only deal with UI state.

import {
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser';

import { api } from './api';

export interface SessionInfo {
  authenticated: boolean;
  username: string | null;
}

export interface InviteInfo {
  valid: boolean;
  /** Set when the invite adds a device to an existing account. */
  forUsername?: string | null;
}

export const getSession = () =>
  api<SessionInfo>('session').catch((): SessionInfo => ({ authenticated: false, username: null }));

export const getInvite = (token: string) => api<InviteInfo>(`invite?token=${encodeURIComponent(token)}`);

/** Runs the sign-in ceremony; resolves to where the server says to go next. */
export async function signIn(next: string): Promise<string> {
  const optionsJSON = await api<PublicKeyCredentialRequestOptionsJSON>(
    `generate-auth-options?next=${encodeURIComponent(next)}`,
  );
  const response = await startAuthentication({ optionsJSON });
  const result = await api<{ redirect: string }>('verify-auth', { method: 'POST', body: response });
  return result.redirect;
}

/** Runs the registration ceremony for an invite; username only for new accounts. */
export async function register(token: string, username: string | null): Promise<string> {
  const query = new URLSearchParams({ token });
  if (username) query.set('username', username);
  const optionsJSON = await api<PublicKeyCredentialCreationOptionsJSON>(`generate-reg-options?${query}`);
  const response = await startRegistration({ optionsJSON });
  const result = await api<{ redirect: string }>('verify-reg', { method: 'POST', body: response });
  return result.redirect;
}

export const logout = () => api('logout', { method: 'POST' });

/** Turns WebAuthn and network errors into something a person can act on. */
export function describeError(err: unknown): string {
  const e = err as Error | undefined;
  switch (e?.name) {
    case 'NotAllowedError':
    case 'AbortError':
      return 'Passkey request was canceled or timed out.';
    case 'InvalidStateError':
      return 'This device already has a passkey for this account — just sign in.';
    case 'SecurityError':
      return "This address doesn't match the server's passkey domain.";
    case 'NotSupportedError':
      return "This device or browser doesn't support passkeys.";
    default:
      return e?.message || 'Something went wrong. Please try again.';
  }
}

/** Only same-origin paths — the server checks this too. */
export function go(target: string | undefined): void {
  location.assign(target && target.startsWith('/') && !target.startsWith('//') ? target : '/');
}

export const USERNAME_PATTERN = '[A-Za-z0-9][A-Za-z0-9._\\-]{1,31}';
export const USERNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{1,31}$/;
export const USERNAME_HINT = 'Username must be 2–32 characters: letters, digits, dot, dash or underscore.';
