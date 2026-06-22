import { useRef, useState } from 'react'
import { StagePayload } from '../api/stage'

interface Props {
  mode:              'stageless' | 'staged'
  setMode:           (m: 'stageless' | 'staged') => void
  shellcodeHex:      string
  setShellcodeHex:   (s: string) => void
  binFilename:       string | null
  setBinFilename:    (s: string | null) => void
  stages:            StagePayload[]
  activeStagePid:    string | null
  setActiveStagePid: (pid: string) => void
  onFileUpload:      (file: File) => void
  onStageUpload:     (file: File) => Promise<void> | void
  onStageDelete:     (pid: string) => Promise<void> | void
}

function bytesToSize(n: number): string {
  if (!n) return '0 B'
  const k = 1024, units = ['B','KB','MB','GB']
  const i = Math.floor(Math.log(n)/Math.log(k))
  return (n/Math.pow(k,i)).toFixed(i?2:0) + ' ' + units[i]
}

function ModeSelector({ mode, setMode, stageCount }: { mode: 'stageless' | 'staged'; setMode: (m:'stageless'|'staged')=>void; stageCount:number }) {
  return (
    <div className="mode-grid">
      <button className={'mode-card' + (mode==='stageless' ? ' active' : '')} onClick={() => setMode('stageless')}>
        <div className="mode-head">
          <span className="mode-num">A</span>
          <span className="mode-name">Stageless</span>
          {mode==='stageless' && <span className="mode-tag">in use</span>}
        </div>
        <div className="mode-desc">Shellcode is embedded directly in the loader artifact. Single self-contained binary — no network fetch at runtime.</div>
        <div className="mode-foot">
          <span className="mode-pro">Air-gapped delivery</span>
          <span className="mode-pro">No C2 dependency on exec</span>
          <span className="mode-con">Larger artifact size</span>
        </div>
      </button>
      <button className={'mode-card' + (mode==='staged' ? ' active' : '')} onClick={() => setMode('staged')}>
        <div className="mode-head">
          <span className="mode-num">B</span>
          <span className="mode-name">Staged</span>
          {mode==='staged' && <span className="mode-tag">{stageCount} hosted</span>}
        </div>
        <div className="mode-desc">
          Tiny loader. At detonation it fetches shellcode from <code>/api/v1/stage/&lt;pid&gt;</code> over a signed JWT. Many payloads on one URL.
        </div>
        <div className="mode-foot">
          <span className="mode-pro">Small loader</span>
          <span className="mode-pro">Many payloads, one endpoint</span>
          <span className="mode-con">Needs reachable stage host</span>
        </div>
      </button>
    </div>
  )
}

function StageBadge({ status }: { status: 'staged' | 'embedded' }) {
  return (
    <span className={'stage-status' + (status === 'embedded' ? ' embedded' : '')}>
      <span className="led"/>{status}
    </span>
  )
}

export default function PayloadSection({
  mode, setMode,
  shellcodeHex, setShellcodeHex,
  binFilename, setBinFilename,
  stages, activeStagePid, setActiveStagePid,
  onFileUpload, onStageUpload, onStageDelete,
}: Props) {
  const inputRef = useRef<HTMLInputElement>(null)
  const stageInputRef = useRef<HTMLInputElement>(null)
  const [drag, setDrag] = useState(false)
  const isStageless = mode === 'stageless'
  const empty = isStageless ? !shellcodeHex : stages.length === 0

  return (
    <section className="section" id="payload">
      <div className="section-label">
        <span className="num">01</span>
        <span className="name">Payload</span>
        {!empty && <StageBadge status={isStageless ? 'embedded' : 'staged'}/>}
        <span className="meta">Pick delivery mode, then upload raw shellcode</span>
      </div>

      <ModeSelector mode={mode} setMode={setMode} stageCount={stages.length}/>

      <div className="payload-card">
        {empty ? (
          <div
            className={'dropzone' + (drag ? ' drag' : '')}
            onClick={() => (isStageless ? inputRef : stageInputRef).current?.click()}
            onDragOver={e => { e.preventDefault(); setDrag(true) }}
            onDragLeave={() => setDrag(false)}
            onDrop={e => {
              e.preventDefault(); setDrag(false)
              const f = e.dataTransfer.files[0]
              if (!f) return
              isStageless ? onFileUpload(f) : onStageUpload(f)
            }}
          >
            <svg className="ico-up" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
              <path d="M12 16V4m0 0L7 9m5-5l5 5M4 20h16"/>
            </svg>
            <div className="big">Drop shellcode here, or click to browse</div>
            <div className="small">.bin · .raw · .sc — up to 10 MB · stays in your browser</div>
            <input ref={inputRef} type="file" hidden accept=".bin,.raw,.sc"
              onChange={e => { const f = e.target.files?.[0]; if (f) onFileUpload(f); e.target.value='' }}/>
            <input ref={stageInputRef} type="file" hidden accept=".bin,.raw,.sc"
              onChange={e => { const f = e.target.files?.[0]; if (f) onStageUpload(f); e.target.value='' }}/>
          </div>
        ) : isStageless ? (
          <div className="staged">
            <div className="staged-head">
              <div className="filebox">BIN</div>
              <div className="meta">
                <div className="fname">{binFilename ?? 'shellcode.bin'}</div>
                <div className="fdetails">Raw shellcode · x64 · {bytesToSize(shellcodeHex.length / 2)}</div>
              </div>
              <div className="actions">
                <button className="btn btn-sm btn-ghost" onClick={() => { setShellcodeHex(''); setBinFilename(null) }}>
                  <svg className="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                    <path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/>
                  </svg>
                  <span>Replace</span>
                </button>
              </div>
            </div>
            <div className="payload-stats">
              <div className="stat"><div className="lbl">Size</div><div className="val">{bytesToSize(shellcodeHex.length / 2)}</div></div>
              <div className="stat"><div className="lbl">Hex chars</div><div className="val small">{shellcodeHex.length.toLocaleString()}</div></div>
              <div className="stat"><div className="lbl">Arch</div><div className="val">x64</div></div>
              <div className="stat"><div className="lbl">Mode</div><div className="val small">Embedded</div></div>
            </div>
          </div>
        ) : (
          <div className="staged stage-multi">
            <div className="stage-list-head">
              <div className="slh-title">Staged payloads</div>
              <div className="slh-meta">Click a row to mark it active for the next forge</div>
            </div>
            <div className="stage-list">
              {stages.map(p => (
                <div
                  key={p.pid}
                  className={'stage-row' + (activeStagePid === p.pid ? ' active' : '')}
                  onClick={() => setActiveStagePid(p.pid)}
                >
                  <div className="stage-radio"/>
                  <div className="filebox">BIN</div>
                  <div className="stage-info">
                    <div className="fname">{p.name}</div>
                    <div className="fdetails">pid <span className="mono">{p.pid}</span> · {bytesToSize(p.size)} · {p.arch}</div>
                  </div>
                  <div className="stage-tags">
                    {activeStagePid === p.pid && <span className="risk low">active</span>}
                    <span className="stage-status sm"><span className="led"/>hosted</span>
                  </div>
                  <button className="btn btn-sm btn-ghost"
                    onClick={(e) => { e.stopPropagation(); onStageDelete(p.pid) }}>Unstage</button>
                </div>
              ))}
            </div>
            <div className="stage-add" onClick={() => stageInputRef.current?.click()}>
              <span className="plus">+</span>
              <span>Stage another payload</span>
              <span className="stage-add-hint">.bin · .raw · .sc</span>
              <input ref={stageInputRef} type="file" hidden accept=".bin,.raw,.sc"
                onChange={e => { const f = e.target.files?.[0]; if (f) onStageUpload(f); e.target.value='' }}/>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
