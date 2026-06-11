import { useRef } from 'react'
import { StagePayload } from '../api/stage'

type Mode = 'stageless' | 'staged'

interface Props {
  mode:                Mode
  onModeChange:        (m: Mode) => void
  shellcodeHex:        string
  onShellcodeHexChange:(hex: string) => void
  binFilename:         string | null
  stages:              StagePayload[]
  onFileUpload:        (file: File) => void
  onStageUpload:       (file: File) => void
  onStageDelete:       (pid: string) => void
}

export default function PayloadSection({
  mode, onModeChange, shellcodeHex, onShellcodeHexChange,
  binFilename, stages, onFileUpload, onStageUpload, onStageDelete,
}: Props) {
  const fileRef  = useRef<HTMLInputElement>(null)
  const stageRef = useRef<HTMLInputElement>(null)

  function handleBinChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (f) onFileUpload(f)
  }

  function handleStageChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (f) onStageUpload(f)
  }

  return (
    <section id="section-payload" className="space-y-4">
      <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        01 — Payload
      </h2>

      {/* Mode cards */}
      <div className="grid grid-cols-2 gap-3">
        {(['stageless', 'staged'] as Mode[]).map(m => (
          <button
            key={m}
            type="button"
            onClick={() => onModeChange(m)}
            className="rounded-xl p-4 text-left transition"
            style={{
              border: `1px solid ${mode === m ? 'var(--blue-500)' : 'var(--border)'}`,
              backgroundColor: mode === m ? 'var(--blue-alpha)' : 'var(--surface)',
              color: mode === m ? 'var(--blue-500)' : 'var(--ink-muted)',
            }}
          >
            <div className="font-semibold text-sm capitalize">{m === 'stageless' ? 'A: Stageless' : 'B: Staged'}</div>
            <div className="text-xs mt-1" style={{ color: 'var(--ink-muted)' }}>
              {m === 'stageless' ? 'Shellcode embedded in loader' : 'Shellcode fetched at runtime'}
            </div>
          </button>
        ))}
      </div>

      {/* Stageless: hex input + file upload */}
      {mode === 'stageless' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-xs" style={{ color: 'var(--ink-muted)' }}>Shellcode (hex)</label>
            <div className="flex items-center gap-2">
              {binFilename && (
                <span className="text-xs font-mono truncate max-w-[160px]" style={{ color: 'var(--blue-500)' }}>
                  {binFilename}
                </span>
              )}
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                className="text-xs px-2 py-1 rounded-lg transition"
                style={{ border: '1px solid var(--border)', color: 'var(--ink-muted)' }}
              >
                Upload .bin
              </button>
              <input ref={fileRef} type="file" accept=".bin,application/octet-stream" className="hidden" onChange={handleBinChange} />
            </div>
          </div>
          <textarea
            rows={4}
            placeholder="fc4883e4f0e8… or upload a .bin file"
            value={shellcodeHex}
            onChange={e => onShellcodeHexChange(e.target.value)}
            className="w-full rounded-lg px-3 py-2 text-xs font-mono focus:outline-none resize-none"
            style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--ink)' }}
          />
        </div>
      )}

      {/* Staged: list + upload button */}
      {mode === 'staged' && (
        <div className="space-y-2">
          {stages.map(s => (
            <div
              key={s.pid}
              className="flex items-center justify-between rounded-lg px-3 py-2"
              style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface-2)' }}
            >
              <div>
                <span className="text-xs font-mono" style={{ color: 'var(--ink)' }}>{s.name}</span>
                <span className="text-xs ml-2 font-mono" style={{ color: 'var(--ink-muted)' }}>{s.pid}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs" style={{ color: 'var(--ink-muted)' }}>{(s.size / 1024).toFixed(1)} KB</span>
                <button
                  type="button"
                  onClick={() => onStageDelete(s.pid)}
                  className="text-xs px-2 py-0.5 rounded transition"
                  style={{ color: 'var(--danger)', border: '1px solid var(--danger)' }}
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
          <button
            type="button"
            onClick={() => stageRef.current?.click()}
            className="w-full rounded-lg py-2 text-xs font-medium transition"
            style={{ border: '1px dashed var(--border)', color: 'var(--ink-muted)' }}
          >
            + Stage another .bin
          </button>
          <input ref={stageRef} type="file" accept=".bin,application/octet-stream" className="hidden" onChange={handleStageChange} />
        </div>
      )}
    </section>
  )
}
