import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../store/auth'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const { login } = useAuth()
  const navigate = useNavigate()

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
    <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: '#0a0a0f' }}>
      <div className="w-full max-w-sm rounded-2xl p-8 shadow-2xl" style={{ backgroundColor: '#12121a', border: '1px solid #1e1e2e' }}>
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-bold tracking-tight" style={{ color: '#e2e8f0' }}>DefCrow</h1>
          <p className="text-sm mt-1" style={{ color: '#64748b' }}>Loader Generation Platform</p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label htmlFor="username" className="block text-sm mb-1" style={{ color: '#64748b' }}>Username</label>
            <input id="username" type="text" required autoComplete="username"
              value={username} onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none transition"
              style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#e2e8f0' }}
            />
          </div>
          <div>
            <label htmlFor="password" className="block text-sm mb-1" style={{ color: '#64748b' }}>Password</label>
            <input id="password" type="password" required autoComplete="current-password"
              value={password} onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none transition"
              style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#e2e8f0' }}
            />
          </div>
          {error && (
            <p className="text-sm rounded-lg px-3 py-2 border"
               style={{ color: '#dc2626', backgroundColor: 'rgba(127,0,0,0.2)', borderColor: '#7f1d1d' }}>
              {error}
            </p>
          )}
          <button type="submit" disabled={loading}
            className="w-full py-2.5 rounded-lg text-white font-medium text-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ backgroundColor: '#7c3aed' }}>
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}
