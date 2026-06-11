import { useRef, useEffect } from 'react'
import DeliveryCard from './DeliveryCard'
import { createSmugLink } from '../api/smuggler'

export interface LogLine { ts: string; tag: string; msg: string }
export type BuildStatus = 'idle' | 'building' | 'done' | 'error'

const TAG_COLOR: Record<string, string> = {
  info: 'var(--blue-500)', ok: 'var(--ok)', warn: 'var(--warn)', step: 'var(--blue-500)', err: 'var(--danger)',
}

const STATUS_LABEL: Record<BuildStatus, string> = {
  idle: 'Idle', building: 'Building', done: 'Complete', error: 'Error',
}

const STATUS_COLOR: Record<BuildStatus, string> = {
  idle: 'var(--ink-muted)', building: 'var(--warn)', done: 'var(--ok)', error: 'var(--danger)',
}

interface Props {
  logs:         LogLine[]
  status:       BuildStatus
  canForge:     boolean
  onForge:      () => void
  artifactId:   string | null
  artifactName: string | null
  smugHost:     string
}

export default function BuildConsole({ logs, status, canForge, onForge, artifactId, artifactName, smugHost }: Props) {
  const logRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])

  return (
    <div
      className="sticky top-[60px] flex flex-col rounded-xl overflow-hidden"
      style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface)', height: 'calc(100vh - 80px)' }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
        <span className="text-xs font-semibold" style={{ color: 'var(--ink)' }}>Build console</span>
        <span className="text-xs font-mono" style={{ color: STATUS_COLOR[status] }}>
          ● {STATUS_LABEL[status]}
        </span>
      </div>

      {/* Log area */}
      <div ref={logRef} className="flex-1 overflow-y-auto px-3 py-2 font-mono text-xs space-y-0.5">
        {logs.length === 0 && (
          <p className="text-xs" style={{ color: 'var(--ink-muted)' }}>Ready. Configure and hit Forge.</p>
        )}
        {logs.map((l, i) => (
          <div key={i} className="flex gap-2">
            <span style={{ color: 'var(--ink-muted)' }}>{l.ts}</span>
            <span style={{ color: TAG_COLOR[l.tag] ?? 'var(--ink-muted)' }}>[{l.tag}]</span>
            <span style={{ color: 'var(--ink)' }}>{l.msg}</span>
          </div>
        ))}
      </div>

      {/* Artifact card (shown after build) */}
      {status === 'done' && artifactId && artifactName && (
        <div className="px-3 pb-2">
          <div className="rounded-lg px-3 py-2 flex items-center justify-between" style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface-2)' }}>
            <span className="text-xs font-mono truncate" style={{ color: 'var(--ink)' }}>{artifactName}</span>
            <a
              href={`/api/download/${artifactId}`}
              className="text-xs px-2 py-1 rounded transition ml-2"
              style={{ border: '1px solid var(--blue-500)', color: 'var(--blue-500)' }}
            >
              Download
            </a>
          </div>
          <div className="mt-2">
            <DeliveryCard
              artifactName={artifactName}
              stageHost={smugHost}
              downloadId={artifactId}
              onSmuggle={(fakeName) => createSmugLink(artifactId, fakeName)}
            />
          </div>
        </div>
      )}

      {/* Forge button */}
      <div className="px-3 pb-3">
        <button
          type="button"
          onClick={onForge}
          disabled={!canForge || status === 'building'}
          className="w-full py-2.5 rounded-lg font-semibold text-sm transition disabled:opacity-40 disabled:cursor-not-allowed"
          style={{ backgroundColor: 'var(--blue-500)', color: '#fff' }}
        >
          {status === 'building' ? 'Forging…' : 'Forge'}
        </button>
      </div>
    </div>
  )
}
