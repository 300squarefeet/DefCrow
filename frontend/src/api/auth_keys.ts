import { client } from './client'

export interface RequestKeyResponse {
  delivered: boolean
  error?:    string
}

export interface LoginResponse {
  token:    string
  username: string
  role:     string
}

/**
 * Ask the backend to mint a one-time access key and deliver it to Discord.
 * Server returns 200 with `delivered: true` on success, 200 with a generic
 * shape on unknown user (no enumeration), 502 if Discord delivery failed,
 * or 500 if the global webhook is not configured.
 */
export async function requestKey(username: string): Promise<RequestKeyResponse> {
  const { data } = await client.post<RequestKeyResponse>('/auth/request-key', { username })
  return data
}

/**
 * Exchange a delivered key for a session JWT. Server returns 401 on bad/expired/used key.
 */
export async function loginWithKey(username: string, key: string): Promise<LoginResponse> {
  const { data } = await client.post<LoginResponse>('/auth/login', { username, key })
  return data
}
