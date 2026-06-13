import { useRef } from 'react'
import { AppDomainHostBinary, AppDomainReq, appdomainConfigFilename } from '../api/generate'

interface Props { value: AppDomainReq; onChange: (v: AppDomainReq) => void }
const CLR_VERSIONS = ['v2.0.50727', 'v4.0.30319']
const NET_VERSIONS = ['2.0', '3.5', '4.0', '4.5', '4.8']
const HOST_BINARIES: AppDomainHostBinary[] = ['MSBuild.exe', 'FileHistory.exe']
// Captions articulate the tradecraft trade-off, not just the mechanics — what
// the operator gains *and* what artifact each host binary leaves behind.
const HOST_CAPTIONS: Record<AppDomainHostBinary, string> = {
  'MSBuild.exe':
    'Framework64\\v4.0.30319\\ — developer-tool plausibility (common on dev/build boxes), but requires admin to drop the .config in Framework64 and parent path screams build host.',
  'FileHistory.exe':
    'System32 origin (low-suspicion parent path), runs without admin once copied — but the copy step itself (System32 → user-writable dir) is the detection artifact EDR will flag.',
}

export default function AppDomainConfig({ value, onChange }: Props) {
  function set<K extends keyof AppDomainReq>(k: K, v: AppDomainReq[K]) { onChange({ ...value, [k]: v }) }
  const host: AppDomainHostBinary = value.host_binary ?? 'MSBuild.exe'
  const configName = appdomainConfigFilename(host)

  // Roving-tabindex refs so left/right arrows move focus between radio buttons
  // (WAI-ARIA radio-group pattern). Tab enters the group on the active option.
  const btnRefs = useRef<Array<HTMLButtonElement | null>>([])
  function onRadioKey(e: React.KeyboardEvent<HTMLButtonElement>, idx: number) {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End') return
    e.preventDefault()
    let nextIdx = idx
    if (e.key === 'ArrowRight') nextIdx = (idx + 1) % HOST_BINARIES.length
    else if (e.key === 'ArrowLeft') nextIdx = (idx - 1 + HOST_BINARIES.length) % HOST_BINARIES.length
    else if (e.key === 'Home') nextIdx = 0
    else if (e.key === 'End') nextIdx = HOST_BINARIES.length - 1
    const next = HOST_BINARIES[nextIdx]
    set('host_binary', next)
    btnRefs.current[nextIdx]?.focus()
  }

  return (
    <div className="rounded-xl p-4 space-y-4" style={{ border: '1px solid rgba(124,58,237,0.4)', backgroundColor: 'rgba(124,58,237,0.05)' }}>
      <p className="text-sm font-semibold" style={{ color: '#7c3aed' }}>AppDomain Configuration</p>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs mb-1" style={{ color: '#64748b' }}>CLR Version</label>
          <select value={value.clr_version} onChange={(e) => set('clr_version', e.target.value)}
            className="w-full rounded-lg px-2 py-1.5 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-400"
            style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#e2e8f0' }}>
            {CLR_VERSIONS.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: '#64748b' }}>.NET Version</label>
          <select value={value.net_version} onChange={(e) => set('net_version', e.target.value)}
            className="w-full rounded-lg px-2 py-1.5 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-400"
            style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#e2e8f0' }}>
            {NET_VERSIONS.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
      </div>
      <div>
        <label id="appdomain-host-binary-label" className="block text-xs mb-1" style={{ color: '#64748b' }}>
          Host binary
        </label>
        <div role="radiogroup" aria-labelledby="appdomain-host-binary-label" className="flex gap-2">
          {HOST_BINARIES.map((hb, idx) => {
            const active = host === hb
            return (
              <button
                type="button"
                role="radio"
                aria-checked={active}
                aria-label={`AppDomain host binary: ${hb}`}
                tabIndex={active ? 0 : -1}
                ref={(el) => { btnRefs.current[idx] = el }}
                key={hb}
                onClick={() => set('host_binary', hb)}
                onKeyDown={(e) => onRadioKey(e, idx)}
                className="flex-1 rounded-lg px-2 py-1.5 text-xs focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-400"
                style={{
                  backgroundColor: active ? 'rgba(124,58,237,0.2)' : '#0a0a0f',
                  border: active ? '1px solid rgba(124,58,237,0.8)' : '1px solid #1e1e2e',
                  color: active ? '#c4b5fd' : '#e2e8f0',
                  fontWeight: active ? 600 : 400,
                }}
              >
                {hb}
              </button>
            )
          })}
        </div>
        <p className="text-xs mt-1.5" style={{ color: '#64748b' }}>{HOST_CAPTIONS[host]}</p>
      </div>
      <div className="rounded-lg p-3" style={{ backgroundColor: 'rgba(180,120,0,0.1)', border: '1px solid rgba(180,120,0,0.4)' }}>
        <p className="text-xs font-medium mb-1" style={{ color: '#fbbf24' }}>Generated Output</p>
        <p className="text-xs" style={{ color: '#64748b' }}>1. <code style={{ color: '#e2e8f0' }}>loader.dll</code> — AppDomainManager via ICLRRuntimeHost2</p>
        <p className="text-xs mt-1" style={{ color: '#64748b' }}>2. <code style={{ color: '#e2e8f0' }}>{configName}</code> — place alongside {host}</p>
      </div>
    </div>
  )
}
