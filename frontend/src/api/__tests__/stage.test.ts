import { describe, it, expect, vi, beforeEach } from 'vitest'
import * as clientModule from '../client'

vi.mock('../client', () => ({
  client: {
    post:   vi.fn(),
    get:    vi.fn(),
    delete: vi.fn(),
  },
}))

const mockedClient = clientModule.client as any

describe('stage API', () => {
  beforeEach(() => vi.clearAllMocks())

  it('uploadStage posts to /v1/stage with FormData', async () => {
    mockedClient.post.mockResolvedValue({ data: { pid: 'abc123', size: 512, name: 'payload.bin', jwt: 'x.y.z', url: '/api/v1/stage/abc123' } })
    const { uploadStage } = await import('../stage')
    const file = new File([new Uint8Array(512)], 'payload.bin')
    const res = await uploadStage(file)
    expect(mockedClient.post).toHaveBeenCalledWith('/v1/stage', expect.any(FormData), expect.objectContaining({ headers: expect.any(Object) }))
    expect(res.pid).toBe('abc123')
  })

  it('listStages calls GET /v1/stage', async () => {
    mockedClient.get.mockResolvedValue({ data: [] })
    const { listStages } = await import('../stage')
    await listStages()
    expect(mockedClient.get).toHaveBeenCalledWith('/v1/stage')
  })

  it('deleteStage calls DELETE /v1/stage/:pid', async () => {
    mockedClient.delete.mockResolvedValue({})
    const { deleteStage } = await import('../stage')
    await deleteStage('abc123')
    expect(mockedClient.delete).toHaveBeenCalledWith('/v1/stage/abc123')
  })

  it('rotateToken posts to /v1/stage/:pid/token', async () => {
    mockedClient.post.mockResolvedValue({ data: { jwt: 'new.jwt.token' } })
    const { rotateToken } = await import('../stage')
    const res = await rotateToken('abc123')
    expect(mockedClient.post).toHaveBeenCalledWith('/v1/stage/abc123/token', undefined, undefined)
    expect(res.jwt).toBe('new.jwt.token')
  })
})
