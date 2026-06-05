import { PeMetadataReq } from '../api/generate'

interface Props { value: PeMetadataReq; onChange: (v: PeMetadataReq) => void; enabled: boolean; onToggle: (v: boolean) => void }

const PRESETS: Record<string, Partial<PeMetadataReq>> = {
  'Microsoft svchost': { company_name: 'Microsoft Corporation', file_description: 'Host Process for Windows Services', product_name: 'Microsoft Windows Operating System', file_version: '10.0.19041.1', original_filename: 'svchost.exe', legal_copyright: '© Microsoft Corporation. All rights reserved.' },
  'Microsoft explorer': { company_name: 'Microsoft Corporation', file_description: 'Windows Explorer', product_name: 'Microsoft Windows Operating System', file_version: '10.0.19041.1', original_filename: 'explorer.exe', legal_copyright: '© Microsoft Corporation. All rights reserved.' },
  'Custom': {},
}

export default function PeMetadata({ value, onChange, enabled, onToggle }: Props) {
  function set<K extends keyof PeMetadataReq>(k: K, v: PeMetadataReq[K]) { onChange({ ...value, [k]: v }) }
  return (
    <div className="rounded-xl p-4 space-y-4" style={{ border: '1px solid #1e1e2e', backgroundColor: '#12121a' }}>
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold" style={{ color: '#e2e8f0' }}>PE Metadata Spoofing</p>
        <button role="switch" aria-checked={enabled} onClick={() => onToggle(!enabled)}
          className="relative inline-flex h-5 w-9 rounded-full transition"
          style={{ backgroundColor: enabled ? '#7c3aed' : '#1e1e2e' }}>
          <span className="absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform"
            style={{ transform: enabled ? 'translateX(16px)' : 'translateX(0)' }} />
        </button>
      </div>
      {enabled && (
        <>
          <div className="flex gap-2 flex-wrap">
            {Object.keys(PRESETS).map((name) => (
              <button key={name} type="button" onClick={() => onChange({ ...value, ...PRESETS[name] })}
                className="text-xs px-2 py-1 rounded transition"
                style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#64748b' }}>
                {name}
              </button>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-3">
            {([['Company', 'company_name'], ['File Description', 'file_description'], ['Product Name', 'product_name'], ['File Version', 'file_version'], ['Original Filename', 'original_filename'], ['Legal Copyright', 'legal_copyright']] as [string, keyof PeMetadataReq][]).map(([label, key]) => (
              <div key={key}>
                <label className="block text-xs mb-1" style={{ color: '#64748b' }}>{label}</label>
                <input type="text" value={value[key] as string}
                  onChange={(e) => set(key, e.target.value as any)}
                  className="w-full rounded-lg px-2 py-1.5 text-xs focus:outline-none"
                  style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#e2e8f0' }} />
              </div>
            ))}
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={value.sign} onChange={(e) => set('sign', e.target.checked)} />
            <span className="text-xs" style={{ color: '#64748b' }}>Self-sign with osslsigncode</span>
          </label>
        </>
      )}
    </div>
  )
}
