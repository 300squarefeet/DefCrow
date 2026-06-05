import { client } from './client'

export interface LoginResponse { token: string; expires_in: number }

export async function login(username: string, password: string): Promise<LoginResponse> {
  const { data } = await client.post<LoginResponse>('/auth/login', { username, password })
  return data
}

export async function logout(): Promise<void> {
  await client.post('/auth/logout').catch(() => {})
  localStorage.removeItem('defcrow_token')
}
