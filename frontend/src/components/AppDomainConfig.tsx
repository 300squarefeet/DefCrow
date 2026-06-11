import { AppDomainReq } from '../api/generate'

interface Props { value: AppDomainReq; onChange: (v: AppDomainReq) => void }
const CLR_VERSIONS = ['v2.0.50727', 'v4.0.30319']
const NET_VERSIONS = ['2.0', '3.5', '4.0', '4.5', '4.8']

export default function AppDomainConfig({ value, onChange }: Props) {
  function set<K extends keyof AppDomainReq>(k: K, v: AppDomainReq[K]) { onChange({ ...value, [k]: v }) }
  return (
    <div className="rounded-xl p-4 space-y-4" style={{ border: '1px solid rgba(124,58,237,0.4)', backgroundColor: 'rgba(124,58,237,0.05)' }}>
      <p className="text-sm font-semibold" style={{ color: '#7c3aed' }}>AppDomain Configuration</p>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs mb-1" style={{ color: '#64748b' }}>CLR Version</label>
          <select value={value.clr_version} onChange={(e) => set('clr_version', e.target.value)}
            className="w-full rounded-lg px-2 py-1.5 text-sm focus:outline-none"
            style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#e2e8f0' }}>
            {CLR_VERSIONS.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: '#64748b' }}>.NET Version</label>
          <select value={value.net_version} onChange={(e) => set('net_version', e.target.value)}
            className="w-full rounded-lg px-2 py-1.5 text-sm focus:outline-none"
            style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#e2e8f0' }}>
            {NET_VERSIONS.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
      </div>
<div className="rounded-lg p-3" style={{ backgroundColor: 'rgba(180,120,0,0.1)', border: '1px solid rgba(180,120,0,0.4)' }}>
        <p className="text-xs font-medium mb-1" style={{ color: '#fbbf24' }}>Generated Output</p>
        <p className="text-xs" style={{ color: '#64748b' }}>1. <code style={{ color: '#e2e8f0' }}>loader.dll</code> — AppDomainManager via ICLRRuntimeHost2</p>
        <p className="text-xs mt-1" style={{ color: '#64748b' }}>2. <code style={{ color: '#e2e8f0' }}>loader.exe.config</code> — .config hijacking profile</p>
      </div>
    </div>
  )
}
