import { client } from './client'

export interface StagePayload {
  pid:        string
  name:       string
  size:       number
  arch:       string
  created_at: string
}

export interface StageUploadResponse {
  pid:  string
  size: number
  name: string
  jwt:  string
  url:  string
}

export async function uploadStage(file: File): Promise<StageUploadResponse> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await client.post<StageUploadResponse>('/v1/stage', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function listStages(): Promise<StagePayload[]> {
  const { data } = await client.get<StagePayload[]>('/v1/stage')
  return data
}

export async function deleteStage(pid: string): Promise<void> {
  await client.delete(`/v1/stage/${pid}`)
}

export async function rotateToken(pid: string): Promise<{ jwt: string }> {
  const { data } = await client.post<{ jwt: string }>(`/v1/stage/${pid}/token`)
  return data
}
