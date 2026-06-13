import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../store/auth'
import CrowLogo from '../components/CrowLogo'

type Step = 'enter-username' | 'enter-key' | 'submitting' | 'error'

const KEY_LEN = 8

export default function LoginPage() {
  const { requestKey, login } = useAuth()
  const navigate              = useNavigate()

  const [step, setStep]        = useState<Step>('enter-username')
  const [username, setUsername] = useState('')
  const [key, setKey]           = useState('')
  const [error, setError]       = useState<string | null>(null)
  const [status, setStatus]     = useState<string | null>(null)
  const [requesting, setRequesting] = useState(false)

  async function handleRequestKey(e: FormEvent) {
    e.preventDefault()
    setError(null); setStatus(null)
    const u = username.trim()
    if (!u) { setError('Enter an operator handle.'); return }
    setRequesting(true)
    try {
      const res = await requestKey(u)
      if (res.delivered) {
        // No toast library — log + inline status string.
        // eslint-disable-next-line no-console
        console.log('key delivered')
        setStatus('Key sent to Discord — check the channel.')
        setStep('enter-key')
      } else {
        setError(res.error || 'Delivery failed — check the Discord webhook.')
      }
    } catch (err) {
      const status = (err as { response?: { status?: number; data?: { error?: string } } })?.response?.status
      const detail = (err as { response?: { data?: { error?: string } } })?.response?.data?.error
      if (status === 429) {
        setError('Too many requests — wait a minute and try again.')
      } else if (status === 500) {
        setError(detail || 'Discord webhook not configured. Contact your admin.')
      } else if (status === 502) {
        setError(detail || 'Discord delivery failed.')
      } else {
        setError('Connection error — is the server running?')
      }
    } finally {
      setRequesting(false)
    }
  }

  async function handleLogin(e: FormEvent) {
    e.preventDefault()
    setError(null)
    const k = key.trim().toUpperCase()
    if (k.length !== KEY_LEN) { setError(`Key must be ${KEY_LEN} characters.`); return }
    setStep('submitting')
    try {
      await login(username.trim(), k)
      navigate('/')
    } catch (err) {
      const status = (err as { response?: { status?: number } })?.response?.status
      setStep('enter-key')
      if (status === 401) {
        setError('Invalid or expired key — request a new one.')
      } else if (status === 429) {
        setError('Too many attempts — wait a minute and try again.')
      } else {
        setError('Connection error — is the server running?')
      }
    }
  }

  function changeUser() {
    setStep('enter-username')
    setKey('')
    setError(null)
    setStatus(null)
  }

  const submitting = step === 'submitting'

  return (
    <div className="login-screen">
      <div className="login-grid-bg"/>
      <div className="login-stack">
        <div className="login-brand">
          <div style={{ width: 56, height: 56, display: 'grid', placeItems: 'center' }}>
            <CrowLogo size={56}/>
          </div>
          <div>
            <div className="login-name">DefCrow</div>
            <div className="login-tag">C2 loader generator — operator console</div>
          </div>
        </div>

        <form
          className="login-card"
          onSubmit={step === 'enter-username' ? handleRequestKey : handleLogin}
          autoComplete="off"
        >
          <div className="login-card-head">
            <div className="login-card-title">
              {step === 'enter-username' ? 'Sign in' : 'Enter access key'}
            </div>
            <div className="login-card-sub">
              {step === 'enter-username'
                ? 'Operator handle required. We deliver a one-time key to Discord.'
                : 'Paste the 8-character key from the Discord channel.'}
            </div>
          </div>

          {error && (
            <div className="err" style={{
              display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12,
              padding: '8px 12px', borderRadius: 7,
              background: 'var(--danger-soft)', color: 'var(--danger)',
              border: '1px solid var(--danger)', fontSize: 12.5,
            }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                <circle cx="12" cy="12" r="9"/><path d="M12 7v6"/><path d="M12 17h.01"/>
              </svg>
              <span>{error}</span>
            </div>
          )}

          {status && !error && (
            <div role="status" style={{
              display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12,
              padding: '8px 12px', borderRadius: 7,
              background: 'var(--accent-soft, rgba(124,58,237,0.10))', color: 'var(--accent, #7c3aed)',
              border: '1px solid var(--accent, #7c3aed)', fontSize: 12.5,
            }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                <circle cx="12" cy="12" r="9"/><path d="M9 12l2 2 4-4"/>
              </svg>
              <span>{status}</span>
            </div>
          )}

          {step === 'enter-username' ? (
            <>
              <label className="login-field">
                <span className="login-label">Operator handle</span>
                <div className="login-input-wrap">
                  <span className="login-input-ico">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                      <circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>
                    </svg>
                  </span>
                  <input
                    className="login-input"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    placeholder="e.g. crow.ops"
                    autoComplete="username" autoFocus required
                  />
                </div>
              </label>

              <button
                className="btn btn-primary login-submit"
                disabled={requesting}
                type="submit"
              >
                {requesting ? (
                  <><span className="spin"/><span>Requesting key…</span></>
                ) : (
                  <>
                    <span>Request key</span>
                    <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M5 12h14m-6-6l6 6-6 6"/>
                    </svg>
                  </>
                )}
              </button>
            </>
          ) : (
            <>
              <div style={{
                fontSize: 12, color: 'var(--muted)',
                marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <span>Operator: <strong style={{ color: 'var(--text, inherit)' }}>{username}</strong></span>
                <span>·</span>
                <button
                  type="button"
                  onClick={changeUser}
                  style={{
                    background: 'none', border: 'none', padding: 0,
                    color: 'var(--blue-500, #3b82f6)', cursor: 'pointer',
                    fontSize: 12, textDecoration: 'underline',
                  }}
                >
                  Change
                </button>
              </div>

              <label className="login-field">
                <span className="login-label">Access key</span>
                <div className="login-input-wrap">
                  <span className="login-input-ico">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                      <rect x="5" y="11" width="14" height="9" rx="2"/>
                      <path d="M8 11V7a4 4 0 018 0v4"/>
                    </svg>
                  </span>
                  <input
                    className="login-input mono"
                    value={key}
                    onChange={e => setKey(e.target.value.toUpperCase().slice(0, KEY_LEN))}
                    placeholder="ABCD2345"
                    maxLength={KEY_LEN}
                    autoComplete="one-time-code"
                    autoFocus
                    required
                    style={{ letterSpacing: '0.18em', textTransform: 'uppercase' }}
                  />
                </div>
              </label>

              <button
                className="btn btn-primary login-submit"
                disabled={submitting || key.length !== KEY_LEN}
                type="submit"
              >
                {submitting ? (
                  <><span className="spin"/><span>Authenticating…</span></>
                ) : (
                  <>
                    <span>Sign in</span>
                    <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M5 12h14m-6-6l6 6-6 6"/>
                    </svg>
                  </>
                )}
              </button>
            </>
          )}

          <div className="login-meta">
            <span><span className="led"/>TLS 1.3 · session JWT (HS256) · one-time Discord key</span>
          </div>
        </form>

        <div className="login-foot">
          DefCrow is for authorized red-team engagements and security research only.
        </div>
      </div>
    </div>
  )
}
