import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../store/auth'
import CrowLogo from '../components/CrowLogo'
import {
  adminListUsers,
  adminAddUser,
  adminDeleteUser,
  adminGetAuthSettings,
  adminSetAuthSettings,
  adminTestAuthWebhook,
  type UserRecord,
  type UserRole,
} from '../api/admin'

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
  } catch { return { ...DEFAULT_SETTINGS } }
}

const EXTS = ['pdf', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'iso', 'zip']

export default function SettingsPage() {
  const navigate = useNavigate()
  const { logout, user, isAdmin } = useAuth()

  const initial = loadSettings()
  const [defaultExt, setDefaultExt] = useState(initial.defaultExt)
  const [stageHost, setStageHost]   = useState(initial.stageHost || (typeof window !== 'undefined' ? window.location.host : ''))
  const [smugHost, setSmugHost]     = useState(initial.smugglerHost || (typeof window !== 'undefined' ? window.location.host : ''))
  const [discordEnabled, setDiscordEnabled] = useState(initial.discord.enabled)
  const [webhook, setWebhook]       = useState(initial.discord.webhook)
  const [channel, setChannel]       = useState(initial.discord.channel)
  const [saved, setSaved]           = useState(false)
  const [test, setTest]             = useState<{ ok: boolean; msg: string } | null>(null)

  function saveAll() {
    const s: Settings = {
      defaultExt,
      stageHost,
      smugglerHost: smugHost,
      discord: { enabled: discordEnabled, webhook, channel },
    }
    localStorage.setItem('dc_settings', JSON.stringify(s))
    localStorage.setItem('defcrow_stage_host', stageHost)
    localStorage.setItem('defcrow_smug_host',  smugHost)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  function testWebhook() {
    if (!webhook) { setTest({ ok: false, msg: 'no webhook' }); return }
    if (!/^https:\/\/discord(?:app)?\.com\/api\/webhooks\//.test(webhook)) {
      setTest({ ok: false, msg: 'malformed URL' }); return
    }
    setTest({ ok: true, msg: 'looks valid (browser sandboxed)' })
  }

  return (
    <div style={{ backgroundColor: 'var(--bg)', minHeight: '100vh' }}>
      <header className="app-header">
        <div className="brand">
          <div className="brand-mark"><CrowLogo size={32}/></div>
          <div className="brand-text">
            <div className="brand-name">Settings</div>
            <div className="brand-sub">Integrations &amp; delivery</div>
          </div>
        </div>
        <div/>
        <div className="app-tools">
          <button className="btn btn-sm" onClick={() => navigate('/')}>← Back to forge</button>
          <button className="btn btn-sm" onClick={logout}>Sign out</button>
        </div>
      </header>

      <main style={{ padding: '32px 24px', maxWidth: 720, margin: '0 auto' }}>
        <div className="section-label">
          <span className="num">·</span>
          <span className="name">Operator</span>
          <span className="meta">{user?.username ?? 'operator'}{user?.role ? ` · ${user.role}` : ''}</span>
        </div>

        <div className="section">
          <div className="section-label">
            <span className="num">01</span>
            <span className="name">Delivery defaults</span>
          </div>
          <div className="payload-card" style={{ padding: 18 }}>
            <div>
              <span className="login-label" style={{ display: 'block', marginBottom: 8 }}>Default filename extension</span>
              <div className="ext-picker">
                {EXTS.map(x => (
                  <button key={x}
                    className={'ext-chip' + (defaultExt === x ? ' active' : '')}
                    onClick={() => setDefaultExt(x)}>.{x}</button>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="section">
          <div className="section-label">
            <span className="num">02</span>
            <span className="name">Hosts</span>
          </div>
          <div className="payload-card" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <span className="login-label" style={{ display: 'block', marginBottom: 6 }}>Stage host (loader fetches from here)</span>
              <div className="login-input-wrap">
                <input className="login-input mono" value={stageHost}
                  onChange={e => setStageHost(e.target.value)}
                  placeholder="api.internal" />
              </div>
            </div>
            <div>
              <span className="login-label" style={{ display: 'block', marginBottom: 6 }}>Smuggler host (delivery URL host)</span>
              <div className="login-input-wrap">
                <input className="login-input mono" value={smugHost}
                  onChange={e => setSmugHost(e.target.value)}
                  placeholder="cdn.internal" />
              </div>
            </div>
          </div>
        </div>

        <div className="section">
          <div className="section-label">
            <span className="num">03</span>
            <span className="name">Discord</span>
          </div>
          <div className="payload-card" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div className="toggle-row">
              <div>
                <div className="tr-label">Enable Discord webhook</div>
                <div className="tr-sub">Send smuggler links straight to a channel.</div>
              </div>
              <button className={'toggle' + (discordEnabled ? ' on' : '')} onClick={() => setDiscordEnabled(v => !v)}/>
            </div>
            <div>
              <span className="login-label" style={{ display: 'block', marginBottom: 6 }}>Webhook URL</span>
              <div className="login-input-wrap">
                <input className="login-input mono" value={webhook}
                  onChange={e => setWebhook(e.target.value)}
                  placeholder="https://discord.com/api/webhooks/…" />
              </div>
            </div>
            <div>
              <span className="login-label" style={{ display: 'block', marginBottom: 6 }}>Channel label</span>
              <div className="login-input-wrap">
                <input className="login-input" value={channel}
                  onChange={e => setChannel(e.target.value)}
                  placeholder="#deliveries" />
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <button className="btn btn-sm" onClick={testWebhook}>Test webhook</button>
              {test && (
                <span className={'test-status ' + (test.ok ? 'ok' : 'err')}>
                  <span className="led"/>{test.msg}
                </span>
              )}
            </div>
          </div>
        </div>

        {isAdmin && <OperatorsSection />}
        {isAdmin && <AuthenticationSection />}

        <div style={{ display: 'flex', gap: 10, marginTop: 18 }}>
          <button className="btn btn-primary" onClick={saveAll}>
            {saved ? 'Saved ✓' : 'Save settings'}
          </button>
          <button className="btn" onClick={() => { setDefaultExt('pdf'); setStageHost(''); setSmugHost(''); setDiscordEnabled(false); setWebhook(''); setChannel('#deliveries') }}>Reset</button>
        </div>
      </main>
    </div>
  )
}

/* ---- Admin-only: Operators ---------------------------------------------- */

function OperatorsSection() {
  const { user } = useAuth()
  const [users, setUsers]       = useState<UserRecord[]>([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState<string | null>(null)
  const [newUser, setNewUser]   = useState('')
  const [newRole, setNewRole]   = useState<UserRole>('operator')
  const [adding, setAdding]     = useState(false)
  const [deleting, setDeleting] = useState<string | null>(null)

  async function refresh() {
    setLoading(true); setError(null)
    try {
      const list = await adminListUsers()
      setUsers(list)
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to load operators.'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refresh() }, [])

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    const u = newUser.trim()
    if (!u) { setError('Enter a username.'); return }
    setAdding(true)
    try {
      await adminAddUser(u, newRole)
      setNewUser(''); setNewRole('operator')
      await refresh()
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to add operator.'))
    } finally {
      setAdding(false)
    }
  }

  async function handleDelete(username: string) {
    const confirmed = typeof window !== 'undefined'
      ? window.confirm(`Delete operator "${username}"? This cannot be undone.`)
      : true
    if (!confirmed) return
    setError(null); setDeleting(username)
    try {
      await adminDeleteUser(username)
      await refresh()
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to delete operator.'))
    } finally {
      setDeleting(null)
    }
  }

  return (
    <div className="section">
      <div className="section-label">
        <span className="num">04</span>
        <span className="name">Operators</span>
        <span className="meta">admin only</span>
      </div>
      <div className="payload-card" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14 }}>
        {error && <InlineError message={error} />}

        {loading ? (
          <div style={{ fontSize: 12.5, color: 'var(--muted)' }}>Loading operators…</div>
        ) : (
          <table className="operators-table" style={{ width: '100%', borderCollapse: 'separate', borderSpacing: '0 6px' }}>
            <caption className="visually-hidden" style={{
              position: 'absolute', width: 1, height: 1, overflow: 'hidden',
              clip: 'rect(0 0 0 0)', clipPath: 'inset(50%)', whiteSpace: 'nowrap',
            }}>
              Registered operators
            </caption>
            <thead>
              <tr style={{
                fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--muted)',
              }}>
                <th scope="col" style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>Username</th>
                <th scope="col" style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>Role</th>
                <th scope="col" style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>Created</th>
                <th scope="col" style={{ padding: '6px 8px' }}>
                  <span style={{
                    position: 'absolute', width: 1, height: 1, overflow: 'hidden',
                    clip: 'rect(0 0 0 0)', clipPath: 'inset(50%)', whiteSpace: 'nowrap',
                  }}>Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ fontSize: 12.5, color: 'var(--muted)', padding: '6px 8px' }}>
                    No operators registered.
                  </td>
                </tr>
              ) : users.map(u => {
                const isSelf = u.username === user?.username
                const cellStyle: React.CSSProperties = {
                  padding: '8px',
                  background: 'var(--surface-2, rgba(255,255,255,0.02))',
                  borderTop:    '1px solid var(--border, rgba(255,255,255,0.06))',
                  borderBottom: '1px solid var(--border, rgba(255,255,255,0.06))',
                  fontSize: 12.5,
                }
                return (
                  <tr key={u.username}>
                    <td style={{ ...cellStyle, borderLeft: '1px solid var(--border, rgba(255,255,255,0.06))', borderTopLeftRadius: 6, borderBottomLeftRadius: 6 }}>
                      <span className="mono">{u.username}{isSelf && ' (you)'}</span>
                    </td>
                    <td style={{ ...cellStyle, textTransform: 'capitalize' }}>{u.role}</td>
                    <td style={cellStyle}>
                      <span className="mono" style={{ color: 'var(--muted)' }}>{formatTimestamp(u.created_at)}</span>
                    </td>
                    <td style={{ ...cellStyle, textAlign: 'right', borderRight: '1px solid var(--border, rgba(255,255,255,0.06))', borderTopRightRadius: 6, borderBottomRightRadius: 6 }}>
                      <button
                        className="btn btn-sm"
                        onClick={() => handleDelete(u.username)}
                        disabled={deleting === u.username || isSelf}
                        title={isSelf ? "Can't delete yourself" : 'Delete operator'}
                      >
                        {deleting === u.username ? 'Deleting…' : 'Delete'}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}

        <form
          onSubmit={handleAdd}
          style={{ display: 'flex', gap: 8, alignItems: 'flex-end', marginTop: 6, flexWrap: 'wrap' }}
        >
          <div style={{ flex: 1, minWidth: 180 }}>
            <span className="login-label" style={{ display: 'block', marginBottom: 6 }}>New operator handle</span>
            <div className="login-input-wrap">
              <input
                className="login-input mono"
                value={newUser}
                onChange={e => setNewUser(e.target.value)}
                placeholder="e.g. alice"
                autoComplete="off"
              />
            </div>
          </div>
          <div style={{ minWidth: 140 }}>
            <span className="login-label" style={{ display: 'block', marginBottom: 6 }}>Role</span>
            <div className="login-input-wrap">
              <select
                className="login-input"
                value={newRole}
                onChange={e => setNewRole(e.target.value as UserRole)}
              >
                <option value="operator">Operator</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          </div>
          <button className="btn btn-primary" type="submit" disabled={adding}>
            {adding ? 'Adding…' : 'Add operator'}
          </button>
        </form>
      </div>
    </div>
  )
}

/* ---- Admin-only: Authentication ----------------------------------------- */

function AuthenticationSection() {
  const [webhookUrl, setWebhookUrl] = useState('')
  const [original, setOriginal]     = useState('')
  const [loading, setLoading]       = useState(true)
  const [saving, setSaving]         = useState(false)
  const [testing, setTesting]       = useState(false)
  const [error, setError]           = useState<string | null>(null)
  const [status, setStatus]         = useState<string | null>(null)
  const [testRes, setTestRes]       = useState<{ ok: boolean; msg: string } | null>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const dto = await adminGetAuthSettings()
        if (cancelled) return
        const wh = dto.discord_webhook ?? ''
        setWebhookUrl(wh)
        setOriginal(wh)
      } catch (err) {
        if (!cancelled) setError(extractErrorMessage(err, 'Failed to load auth settings.'))
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  async function handleSave() {
    setError(null); setStatus(null); setSaving(true)
    try {
      const wh = webhookUrl.trim()
      const dto = await adminSetAuthSettings({ discord_webhook: wh.length > 0 ? wh : null })
      const next = dto.discord_webhook ?? ''
      setWebhookUrl(next); setOriginal(next)
      setStatus('Saved.')
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to save auth settings.'))
    } finally {
      setSaving(false)
    }
  }

  async function handleTest() {
    setError(null); setStatus(null); setTestRes(null); setTesting(true)
    try {
      const res = await adminTestAuthWebhook()
      if (res.ok) {
        setTestRes({ ok: true, msg: 'webhook reachable — test post sent' })
      } else {
        setTestRes({ ok: false, msg: res.error || 'webhook test failed' })
      }
    } catch (err) {
      setTestRes({ ok: false, msg: extractErrorMessage(err, 'webhook test failed') })
    } finally {
      setTesting(false)
    }
  }

  const dirty = webhookUrl.trim() !== original.trim()

  return (
    <div className="section">
      <div className="section-label">
        <span className="num">05</span>
        <span className="name">Authentication</span>
        <span className="meta">global · admin only</span>
      </div>
      <div className="payload-card" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ fontSize: 12.5, color: 'var(--muted)' }}>
          DefCrow delivers one-time login keys to a single Discord channel for every operator.
        </div>

        {error && <InlineError message={error} />}
        {status && !error && <InlineStatus message={status} />}

        <div>
          <span className="login-label" style={{ display: 'block', marginBottom: 6 }}>Auth Discord webhook URL</span>
          <div className="login-input-wrap">
            <input
              data-testid="auth-webhook-input"
              className="login-input mono"
              value={webhookUrl}
              onChange={e => setWebhookUrl(e.target.value)}
              placeholder={loading ? 'Loading…' : 'https://discord.com/api/webhooks/…'}
              disabled={loading}
            />
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button
            className="btn btn-primary"
            onClick={handleSave}
            disabled={loading || saving || !dirty}
          >
            {saving ? 'Saving…' : 'Save webhook'}
          </button>
          <button
            data-testid="auth-webhook-test"
            className="btn btn-sm"
            onClick={handleTest}
            disabled={loading || testing || webhookUrl.trim().length === 0}
          >
            {testing ? 'Testing…' : 'Test webhook'}
          </button>
          {testRes && (
            <span className={'test-status ' + (testRes.ok ? 'ok' : 'err')}>
              <span className="led"/>{testRes.msg}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

/* ---- helpers ------------------------------------------------------------ */

function InlineError({ message }: { message: string }) {
  return (
    <div className="err" style={{
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '8px 12px', borderRadius: 7,
      background: 'var(--danger-soft)', color: 'var(--danger)',
      border: '1px solid var(--danger)', fontSize: 12.5,
    }}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
        <circle cx="12" cy="12" r="9"/><path d="M12 7v6"/><path d="M12 17h.01"/>
      </svg>
      <span>{message}</span>
    </div>
  )
}

function InlineStatus({ message }: { message: string }) {
  return (
    <div role="status" style={{
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '8px 12px', borderRadius: 7,
      background: 'var(--accent-soft, rgba(124,58,237,0.10))',
      color: 'var(--accent, #7c3aed)',
      border: '1px solid var(--accent, #7c3aed)', fontSize: 12.5,
    }}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
        <circle cx="12" cy="12" r="9"/><path d="M9 12l2 2 4-4"/>
      </svg>
      <span>{message}</span>
    </div>
  )
}

function extractErrorMessage(err: unknown, fallback: string): string {
  const e = err as {
    response?: { status?: number; data?: { error?: string; message?: string } }
    message?:  string
  }
  const detail = e?.response?.data?.error ?? e?.response?.data?.message
  if (detail) return detail
  const status = e?.response?.status
  if (status === 401) return 'Unauthorized — log back in.'
  if (status === 403) return 'Forbidden — admin role required.'
  if (status === 404) return 'Endpoint not available on this server.'
  if (status === 409) return 'Conflict — that username already exists.'
  if (status === 422) return 'Validation failed — check the inputs.'
  return e?.message ?? fallback
}

function formatTimestamp(ts: string): string {
  if (!ts) return ''
  try {
    const d = new Date(ts)
    if (isNaN(d.getTime())) return ts
    return d.toISOString().replace('T', ' ').slice(0, 16) + 'Z'
  } catch { return ts }
}
