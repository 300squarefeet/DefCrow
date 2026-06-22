import { useEffect, useState } from 'react'
import { StagePayload } from '../api/stage'

interface Props {
  stages:        StagePayload[]
  tokens:        Record<string, string>
  stageHost:     string
  onRotate:      (pid: string) => void
  selectedPid:   string | null
  onSelect:      (pid: string) => void
}

function bytesToSize(n: number): string {
  if (!n) return '0 B'
  const k = 1024, units = ['B','KB','MB','GB']
  const i = Math.floor(Math.log(n)/Math.log(k))
  return (n/Math.pow(k,i)).toFixed(i?2:0) + ' ' + units[i]
}

function decodeJwtBody(jwt: string): Record<string, unknown> {
  try {
    const [, payload] = jwt.split('.')
    const s = payload.replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(atob(s + '==='.slice((s.length + 3) % 4)))
  } catch {
    return {}
  }
}
function decodeJwtHeader(jwt: string): Record<string, unknown> {
  try {
    const [header] = jwt.split('.')
    const s = header.replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(atob(s + '==='.slice((s.length + 3) % 4)))
  } catch {
    return {}
  }
}

export default function StageTransferSection({ stages, tokens, stageHost, onRotate, selectedPid, onSelect }: Props) {
  const [expanded, setExpanded] = useState<string | null>(selectedPid)
  useEffect(() => { setExpanded(selectedPid) }, [selectedPid])

  const isLocal = stageHost.includes('localhost') || stageHost.startsWith('127.')
  const scheme  = isLocal ? 'http' : 'https'
  const baseUrl = `${scheme}://${stageHost}/api/v1/stage/`

  return (
    <section className="section" id="transfer">
      <div className="section-label">
        <span className="num">02</span>
        <span className="name">Stage transfer</span>
        <span className="stage-count-pill">{stages.length} {stages.length === 1 ? 'payload' : 'payloads'}</span>
        <span className="meta">One endpoint, many payloads — each addressed by its pid</span>
      </div>

      <div className="transfer-card">
        <div className="endpoint-bar">
          <span className="method-pill">GET</span>
          <span className="endpoint-url">{baseUrl}<span className="param">{'{pid}'}</span></span>
          <span className="endpoint-status"><span className="led"/>operational</span>
          <div className="endpoint-actions">
            <button className="btn btn-sm btn-ghost" onClick={() => navigator.clipboard?.writeText(baseUrl)}>
              <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
                <rect x="8" y="8" width="12" height="12" rx="2"/>
                <path d="M16 8V5a2 2 0 00-2-2H5a2 2 0 00-2 2v9a2 2 0 002 2h3"/>
              </svg>
              <span>Copy base URL</span>
            </button>
          </div>
        </div>

        <div className="endpoint-note">
          Beacon issues a signed <code>GET</code> against the base URL with its <code>pid</code> path segment and a fresh Bearer JWT. The <code>pid</code> stays constant per payload; the JWT (nonce + iat + signature) rotates on every request. Shellcode streams straight into memory.
        </div>

        <div className="stages-table">
          {stages.length === 0 && (
            <div className="tx-empty">
              <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                <rect x="5" y="11" width="14" height="9" rx="2"/>
                <path d="M8 11V7a4 4 0 018 0v4"/>
              </svg>
              <div>
                <div className="big">No payloads staged</div>
                <div className="small">Switch to Staged mode in section 01 and upload .bin payloads to populate this table.</div>
              </div>
            </div>
          )}
          {stages.map((p, i) => {
            const jwt    = tokens[p.pid] ?? ''
            const parts  = jwt.split('.')
            const header = decodeJwtHeader(jwt)
            const body   = decodeJwtBody(jwt)
            const open   = expanded === p.pid
            return (
              <div key={p.pid} className={'tx-row' + (open ? ' open' : '') + (selectedPid === p.pid ? ' active' : '')}>
                <button className="tx-head" onClick={() => setExpanded(open ? null : p.pid)}>
                  <span className={'chev' + (open ? ' open' : '')}>▸</span>
                  <span className="tx-idx">#{String(i+1).padStart(2,'0')}</span>
                  <span className="tx-pid mono">{p.pid}</span>
                  <span className="tx-name">{p.name}</span>
                  <span className="tx-size mono">{bytesToSize(p.size)}</span>
                  <span className="endpoint-status sm"><span className="led"/>200</span>
                  {selectedPid === p.pid && <span className="risk low" style={{ marginLeft: 6 }}>active</span>}
                </button>
                {open && (
                  <div className="tx-body">
                    <div className="endpoint-mini">
                      <span className="method-pill">GET</span>
                      <span className="endpoint-url">{baseUrl}<b>{p.pid}</b></span>
                      <button className="btn btn-sm btn-ghost"
                        onClick={(e) => { e.stopPropagation(); navigator.clipboard?.writeText(baseUrl + p.pid) }}>
                        <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
                          <rect x="8" y="8" width="12" height="12" rx="2"/>
                          <path d="M16 8V5a2 2 0 00-2-2H5a2 2 0 00-2 2v9a2 2 0 002 2h3"/>
                        </svg>
                        <span>Copy</span>
                      </button>
                    </div>
                    <div className="jwt-token">
                      <span className="seg-h">{parts[0]}</span>
                      <span className="dot">.</span>
                      <span className="seg-p">{parts[1]}</span>
                      <span className="dot">.</span>
                      <span className="seg-s">{parts[2]}</span>
                    </div>
                    <div className="jwt-segments">
                      <div className="seg seg-h-wrap">
                        <span className="seg-label">Header</span>
                        <span className="seg-text">{JSON.stringify(header)}</span>
                      </div>
                      <div className="seg seg-p-wrap">
                        <span className="seg-label">Payload</span>
                        <span className="seg-text">{JSON.stringify(body)}</span>
                      </div>
                      <div className="seg seg-s-wrap">
                        <span className="seg-label">Signature</span>
                        <span className="seg-text">HMAC-SHA256(base64Url(header).base64Url(payload), stage_key)</span>
                      </div>
                    </div>
                    <div className="jwt-actions">
                      <button className="btn btn-sm btn-primary" onClick={() => navigator.clipboard?.writeText(jwt)}>
                        <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
                          <rect x="8" y="8" width="12" height="12" rx="2"/>
                          <path d="M16 8V5a2 2 0 00-2-2H5a2 2 0 00-2 2v9a2 2 0 002 2h3"/>
                        </svg>
                        <span>Copy token</span>
                      </button>
                      <button className="btn btn-sm" onClick={() => onRotate(p.pid)}>
                        <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                          <path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 4v5h-5"/>
                        </svg>
                        <span>Rotate JWT</span>
                      </button>
                      {selectedPid !== p.pid && (
                        <button className="btn btn-sm btn-soft" onClick={() => onSelect(p.pid)}>Make active</button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
