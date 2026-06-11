import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTheme } from '../hooks/useTheme'
import { useAuth } from '../store/auth'

function load(key: string, def: string) { return localStorage.getItem(key) ?? def }

export default function SettingsPage() {
  const navigate = useNavigate()
  const { logout } = useAuth()
  const { theme, setTheme } = useTheme()

  const [stageHost,   setStageHost]   = useState(() => load('defcrow_stage_host', 'localhost:8080'))
  const [smugHost,    setSmugHost]    = useState(() => load('defcrow_smug_host', 'localhost:8080'))
  const [discordUrl,  setDiscordUrl]  = useState(() => load('defcrow_discord_url', ''))
  const [saved,       setSaved]       = useState(false)

  function handleSave() {
    localStorage.setItem('defcrow_stage_host', stageHost)
    localStorage.setItem('defcrow_smug_host',  smugHost)
    localStorage.setItem('defcrow_discord_url', discordUrl)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div style={{ backgroundColor: 'var(--bg)', minHeight: '100vh' }}>
      <header className="sticky top-0 z-20 flex items-center justify-between px-6" style={{ height: 60, borderBottom: '1px solid var(--border)', backgroundColor: 'var(--surface)' }}>
        <div className="flex items-center gap-3">
          <button type="button" onClick={() => navigate('/')} className="text-xs" style={{ color: 'var(--ink-muted)' }}>← Back</button>
          <span className="font-semibold text-sm" style={{ color: 'var(--ink)' }}>Settings</span>
        </div>
        <button type="button" onClick={logout} className="text-xs" style={{ color: 'var(--ink-muted)' }}>Sign out</button>
      </header>

      <main className="max-w-xl mx-auto px-6 py-8 space-y-8">
        <section className="space-y-4">
          <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>Integrations</h2>
          <div className="space-y-3">
            {[
              { label: 'Stage host', id: 'stage-host', value: stageHost, onChange: setStageHost, placeholder: 'localhost:8080' },
              { label: 'Smuggler host', id: 'smug-host', value: smugHost, onChange: setSmugHost, placeholder: 'localhost:8080' },
              { label: 'Discord webhook URL', id: 'discord-url', value: discordUrl, onChange: setDiscordUrl, placeholder: 'https://discord.com/api/webhooks/…' },
            ].map(f => (
              <div key={f.id}>
                <label htmlFor={f.id} className="block text-xs mb-1.5" style={{ color: 'var(--ink-muted)' }}>{f.label}</label>
                <input
                  id={f.id} type="text" value={f.value} placeholder={f.placeholder}
                  onChange={e => f.onChange(e.target.value)}
                  className="w-full rounded-lg px-3 py-2 text-sm font-mono focus:outline-none"
                  style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--ink)' }}
                />
              </div>
            ))}
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>Theme</h2>
          <div className="grid grid-cols-2 gap-3">
            {(['hacker', 'clean'] as const).map(t => (
              <button
                key={t}
                type="button"
                onClick={() => setTheme(t)}
                className="rounded-xl p-4 text-left transition"
                style={{
                  border: `1px solid ${theme === t ? 'var(--blue-500)' : 'var(--border)'}`,
                  backgroundColor: theme === t ? 'var(--blue-alpha)' : 'var(--surface)',
                }}
              >
                <div className="font-semibold text-sm capitalize" style={{ color: theme === t ? 'var(--blue-500)' : 'var(--ink)' }}>{t}</div>
                <div className="text-xs mt-1" style={{ color: 'var(--ink-muted)' }}>
                  {t === 'hacker' ? 'Dark — current default' : 'Light — clean SaaS look'}
                </div>
              </button>
            ))}
          </div>
        </section>

        <div className="flex gap-3">
          <button
            type="button"
            onClick={handleSave}
            className="px-4 py-2 rounded-lg text-sm font-medium transition"
            style={{ backgroundColor: 'var(--blue-500)', color: '#fff' }}
          >
            {saved ? 'Saved!' : 'Save'}
          </button>
          <button
            type="button"
            onClick={() => {
              setStageHost('localhost:8080'); setSmugHost('localhost:8080'); setDiscordUrl('')
            }}
            className="px-4 py-2 rounded-lg text-sm transition"
            style={{ border: '1px solid var(--border)', color: 'var(--ink-muted)' }}
          >
            Reset
          </button>
        </div>
      </main>
    </div>
  )
}
