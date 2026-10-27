// Calls to the admin API (GATE_PREFIX/api/admin). The server checks the
// role on every request; the page just reflects what it's allowed to do.

import { api } from './api';
import type { Role } from './passkey';

export interface AdminUser {
  id: number;
  username: string;
  role: Role;
  created_at: number;
  passkeys: number;
  last_used_at: number | null;
}

export interface AdminInvite {
  id: string;
  createdAt: number;
  expiresAt: number;
  /** Set when the invite adds a device to an existing account. */
  forUsername: string | null;
  role: Role;
}

export interface CreatedInvite {
  url: string;
  expiresAt: number;
}

export const listUsers = () => api<{ users: AdminUser[] }>('admin/users').then((r) => r.users);

export const setRole = (id: number, role: Role) => api(`admin/users/${id}/role`, { method: 'POST', body: { role } });

export const deleteUser = (id: number) => api(`admin/users/${id}`, { method: 'DELETE' });

export const listInvites = () => api<{ invites: AdminInvite[] }>('admin/invites').then((r) => r.invites);

export const createInvite = (input: { hours: number; role?: Role; forUserId?: number }) =>
  api<CreatedInvite>('admin/invites', { method: 'POST', body: input });

export const revokeInvite = (id: string) => api(`admin/invites/${encodeURIComponent(id)}`, { method: 'DELETE' });

export const revokeAllInvites = () => api<{ revoked: number }>('admin/invites', { method: 'DELETE' });

export const formatDate = (ms: number | null) =>
  ms ? new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—';
