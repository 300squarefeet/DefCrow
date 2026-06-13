import { client } from './client'

export { requestKey, loginWithKey } from './auth_keys'
export type { RequestKeyResponse, LoginResponse } from './auth_keys'

export async function logout(): Promise<void> {
  await client.post('/auth/logout').catch(() => {})
  localStorage.removeItem('defcrow_token')
  localStorage.removeItem('defcrow_user')
}
