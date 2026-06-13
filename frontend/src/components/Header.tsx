import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../store/auth'
import { useTheme } from '../hooks/useTheme'
import CrowLogo from './CrowLogo'

export type StepId = 'payload' | 'transfer' | 'evasion' | 'output' | 'build'

interface Props {
  active:    StepId
  setActive: (s: StepId) => void
  mode:      'stageless' | 'staged'
}

interface StepDef { id: StepId; label: string; onlyMode?: 'staged' | 'stageless' }
const ALL_STEPS: StepDef[] = [
  { id: 'payload',  label: 'Payload' },
  { id: 'transfer', label: 'Stage transfer', onlyMode: 'staged' },
  { id: 'evasion',  label: 'Evasion' },
  { id: 'output',   label: 'Output' },
  { id: 'build',    label: 'Forge' },
]

function pad2(n: number) { return String(n).padStart(2, '0') }

export default function Header({ active, setActive, mode }: Props) {
  const { user, logout } = useAuth()
  const { theme, setTheme } = useTheme()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])

  const steps = ALL_STEPS
    .filter(s => !s.onlyMode || s.onlyMode === mode)
    .map((s, i) => ({ ...s, num: pad2(i + 1) }))

  const handle = user?.username ?? 'operator'

  return (
    <header className="app-header">
      <div className="brand">
        <div className="brand-mark"><CrowLogo size={32}/></div>
        <div className="brand-text">
          <div className="brand-name">DefCrow</div>
          <div className="brand-sub">C2 loader generator · v0.5</div>
        </div>
      </div>

      <nav className="step-rail">
        {steps.map(s => (
          <button
            key={s.id}
            className={'step' + (active === s.id ? ' active' : '')}
            onClick={() => setActive(s.id)}
          >
            <span className="step-num">{s.num}</span>
            <span>{s.label}</span>
          </button>
        ))}
      </nav>

      <div className="app-tools" ref={ref}>
        <button
          className={'icon-btn' + (open ? ' active' : '')}
          onClick={() => setOpen(o => !o)}
          aria-label="Settings"
        >
          <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>
          </svg>
        </button>
        {open && (
          <div className="settings-menu">
            <div className="sm-user">
              <div className="sm-avatar">{handle.slice(0, 2).toUpperCase()}</div>
              <div>
                <div className="sm-name">{handle}</div>
                <div className="sm-role">session secured</div>
              </div>
            </div>
            <div className="sm-section">Theme</div>
            <div className="sm-theme">
              <button
                className={'theme-card' + (theme === 'clean' ? ' active' : '')}
                onClick={() => setTheme('clean')}
              >
                <div className="swatch swatch-clean"><span/><span/><span/></div>
                <div className="theme-label">
                  <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                    <circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>
                  </svg>
                  <span>Clean</span>
                </div>
                <div className="theme-sub">Light SaaS, blue accent</div>
              </button>
              <button
                className={'theme-card' + (theme === 'hacker' ? ' active' : '')}
                onClick={() => setTheme('hacker')}
              >
                <div className="swatch swatch-hacker"><span/><span/><span/></div>
                <div className="theme-label">
                  <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                    <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>
                  </svg>
                  <span>Hacker</span>
                </div>
                <div className="theme-sub">Dark terminal, neon green</div>
              </button>
            </div>
            <div className="sm-divider"/>
            <Link className="sm-item" to="/settings" onClick={() => setOpen(false)}>
              <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                <circle cx="12" cy="12" r="3"/>
                <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>
              </svg>
              <span>Integrations &amp; delivery</span>
            </Link>
            <button className="sm-item danger" onClick={logout}>
              <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
                <path d="M16 17l5-5-5-5"/>
                <path d="M21 12H9"/>
              </svg>
              <span>Sign out</span>
            </button>
          </div>
        )}
      </div>
    </header>
  )
}
