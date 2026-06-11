import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../store/auth'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState<string | null>(null)
  const [loading,  setLoading]  = useState(false)
  const { login }  = useAuth()
  const navigate   = useNavigate()

  async function handleSubmit(e: FormEvent) {
    e.preventDefault(); setError(null); setLoading(true)
    try {
      await login(username, password)
      navigate('/')
    } catch (err: any) {
      setError(err?.response?.status === 401 ? 'Invalid credentials' : 'Connection error — is the server running?')
    } finally { setLoading(false) }
  }

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: 'var(--bg)' }}>
      <div className="w-full max-w-sm rounded-2xl p-8 shadow-2xl" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>
        <div className="mb-8 text-center">
          <div className="flex justify-center mb-3">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--blue-500)" strokeWidth="1.5">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
            </svg>
          </div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--ink)' }}>DefCrow</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--ink-muted)' }}>Loader Generation Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="username" className="block text-sm mb-1.5" style={{ color: 'var(--ink-muted)' }}>
              Username
            </label>
            <input
              id="username" type="text" required autoComplete="username"
              value={username} onChange={e => setUsername(e.target.value)}
              className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none transition"
              style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--ink)' }}
            />
          </div>
          <div>
            <label htmlFor="password" className="block text-sm mb-1.5" style={{ color: 'var(--ink-muted)' }}>
              Password
            </label>
            <input
              id="password" type="password" required autoComplete="current-password"
              value={password} onChange={e => setPassword(e.target.value)}
              className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none transition"
              style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--ink)' }}
            />
          </div>
          {error && (
            <p className="text-sm rounded-lg px-3 py-2" style={{ color: 'var(--danger)', backgroundColor: 'rgba(220,38,38,0.1)', border: '1px solid var(--danger)' }}>
              {error}
            </p>
          )}
          <button
            type="submit" disabled={loading}
            className="w-full py-2.5 rounded-lg font-medium text-sm text-white transition disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ backgroundColor: 'var(--blue-500)' }}
          >
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="mt-6 text-center text-[10px]" style={{ color: 'var(--ink-muted)' }}>
          For authorized use only.
        </p>
      </div>
    </div>
  )
}
