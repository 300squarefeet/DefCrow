import { useAuth } from '../store/auth'
import { useTheme } from '../hooks/useTheme'

export type StepId = 1 | 2 | 3 | 4 | 5

interface StepDef { id: StepId; label: string; staged?: boolean }

const STEPS: StepDef[] = [
  { id: 1, label: '01 Payload' },
  { id: 2, label: '02 Stage Transfer', staged: true },
  { id: 3, label: '03 Evasion' },
  { id: 4, label: '04 Output' },
  { id: 5, label: '05 Forge' },
]

interface Props {
  currentStep: StepId
  showStageTransfer: boolean
  onStepClick: (step: StepId) => void
}

export default function Header({ currentStep, showStageTransfer, onStepClick }: Props) {
  const { logout }    = useAuth()
  const { theme, setTheme } = useTheme()

  const visible = STEPS.filter(s => !s.staged || showStageTransfer)

  return (
    <header
      className="sticky top-0 z-20 flex items-center gap-4 px-6"
      style={{ height: 60, borderBottom: '1px solid var(--border)', backgroundColor: 'var(--surface)' }}
    >
      {/* Brand */}
      <div className="flex items-center gap-2 shrink-0 w-48">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--blue-500)" strokeWidth="2">
          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
        </svg>
        <span className="font-semibold text-sm" style={{ color: 'var(--ink)' }}>DefCrow</span>
      </div>

      {/* Step rail */}
      <nav className="flex-1 flex justify-center gap-1" aria-label="wizard steps">
        {visible.map(step => {
          const active = currentStep === step.id
          return (
            <button
              key={step.id}
              type="button"
              onClick={() => onStepClick(step.id)}
              className="text-xs px-3 py-1.5 rounded-lg font-medium transition"
              style={{
                border: `1px solid ${active ? 'var(--blue-500)' : 'transparent'}`,
                backgroundColor: active ? 'var(--blue-alpha)' : 'transparent',
                color: active ? 'var(--blue-500)' : 'var(--ink-muted)',
              }}
            >
              {step.label}
            </button>
          )
        })}
      </nav>

      {/* Theme + sign out */}
      <div className="flex items-center gap-3 shrink-0 w-48 justify-end">
        <button
          type="button"
          onClick={() => setTheme(theme === 'hacker' ? 'clean' : 'hacker')}
          className="text-xs px-2 py-1 rounded-lg transition"
          style={{ border: '1px solid var(--border)', color: 'var(--ink-muted)' }}
        >
          {theme === 'hacker' ? 'Clean' : 'Hacker'}
        </button>
        <button type="button" onClick={logout} className="text-xs" style={{ color: 'var(--ink-muted)' }}>
          Sign out
        </button>
      </div>
    </header>
  )
}
