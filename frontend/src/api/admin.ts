import { client } from './client'

export type UserRole = 'admin' | 'operator'

export interface UserRecord {
  username:   string
  role:       UserRole
  created_at: string
}

export interface AuthSettingsDto {
  discord_webhook: string | null
}

export async function adminListUsers(): Promise<UserRecord[]> {
  const { data } = await client.get<UserRecord[]>('/admin/users')
  return data
}

export async function adminAddUser(username: string, role: UserRole): Promise<UserRecord> {
  const { data } = await client.post<UserRecord>('/admin/users', { username, role })
  return data
}

export async function adminDeleteUser(username: string): Promise<void> {
  await client.delete(`/admin/users/${encodeURIComponent(username)}`)
}

export async function adminGetAuthSettings(): Promise<AuthSettingsDto> {
  const { data } = await client.get<AuthSettingsDto>('/admin/settings')
  return data
}

export async function adminSetAuthSettings(settings: AuthSettingsDto): Promise<AuthSettingsDto> {
  const { data } = await client.put<AuthSettingsDto>('/admin/settings', settings)
  return data
}

export interface TestWebhookResponse {
  ok:     boolean
  error?: string
}

/**
 * Triggers a server-side test post to the currently-saved Discord webhook.
 * If the backend route is not yet wired, callers should treat 404 as
 * "save then click the operator request-key flow as a smoke test".
 */
export async function adminTestAuthWebhook(): Promise<TestWebhookResponse> {
  const { data } = await client.post<TestWebhookResponse>('/admin/settings/test-webhook')
  return data
}
