import { StagePayload } from '../api/stage'

interface Props {
  stages:    StagePayload[]
  tokens:    Record<string, string>
  stageHost: string
  onRotate:  (pid: string) => void
}

const JWT_COLORS = ['#7c3aed', '#2f6bff', '#16a34a']

export default function StageTransferSection({ stages, tokens, stageHost, onRotate }: Props) {
  return (
    <section id="section-stage-transfer" className="space-y-4">
      <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        02 — Stage Transfer
      </h2>
      <p className="text-xs" style={{ color: 'var(--ink-muted)' }}>
        Each loader fetches shellcode at runtime using a Bearer JWT. Rotate to generate a new one-hour token. Tokens are signed HMAC-SHA256 — server validates before serving bytes.
      </p>
      {stages.map(s => {
        const jwt    = tokens[s.pid] ?? ''
        const parts  = jwt.split('.')
        const url    = `https://${stageHost}/api/v1/stage/${s.pid}`
        return (
          <div key={s.pid} className="rounded-xl p-4 space-y-3" style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface)' }}>
            {/* Endpoint bar */}
            <div className="flex items-center gap-2 rounded-lg px-3 py-2" style={{ backgroundColor: 'var(--surface-2)' }}>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--blue-alpha)', color: 'var(--blue-500)' }}>GET</span>
              <span className="text-xs font-mono truncate flex-1" style={{ color: 'var(--ink)' }}>{url}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ color: 'var(--ok)', border: '1px solid var(--ok)' }}>staged</span>
            </div>

            {/* JWT display */}
            <div className="rounded-lg px-3 py-2 font-mono text-[10px] break-all leading-relaxed" style={{ backgroundColor: 'var(--surface-2)' }}>
              {parts.map((part, i) => (
                <span key={i}>
                  <span style={{ color: JWT_COLORS[i] ?? 'var(--ink-muted)' }}>{part}</span>
                  {i < parts.length - 1 && <span style={{ color: 'var(--ink-muted)' }}>.</span>}
                </span>
              ))}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2">
              <span className="text-xs" style={{ color: 'var(--ink-muted)' }}>{s.name} · {(s.size / 1024).toFixed(1)} KB</span>
              <div className="flex-1" />
              <button
                type="button"
                onClick={() => navigator.clipboard?.writeText(jwt)}
                className="text-xs px-2 py-1 rounded transition"
                style={{ border: '1px solid var(--border)', color: 'var(--ink-muted)' }}
              >
                Copy JWT
              </button>
              <button
                type="button"
                onClick={() => onRotate(s.pid)}
                className="text-xs px-2 py-1 rounded transition"
                style={{ border: '1px solid var(--blue-500)', color: 'var(--blue-500)' }}
              >
                Rotate
              </button>
            </div>
          </div>
        )
      })}
    </section>
  )
}
