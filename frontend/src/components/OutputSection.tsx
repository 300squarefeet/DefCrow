import { LoaderType, Encryption } from '../api/generate'

interface FormatCard {
  id:       string
  name:     string
  ext:      string
  opsec:    'high' | 'med' | 'low' | 'n/a'
  notes:    string
  loader:   LoaderType
}

const FORMATS: FormatCard[] = [
  { id: 'exe',         name: 'Native EXE',       ext: '.exe',          opsec: 'high', notes: 'Standalone PE. Best for USB / archive initial access.', loader: 'Binary' },
  { id: 'dll',         name: 'Native DLL',       ext: '.dll',          opsec: 'high', notes: 'DllMain or exported entry. Pair with sideloading.',      loader: 'Dll' },
  { id: 'appdomain',   name: 'AppDomainManager', ext: '.dll+.config',  opsec: 'high', notes: 'Hijack signed .NET binary via DLL/CONFIG side-load.',    loader: 'AppDomain' },
  { id: 'wsf',         name: 'WSF script',       ext: '.wsf',          opsec: 'med',  notes: 'wscript/cscript. JScript+VBS hybrid.',                  loader: 'Wsf' },
  { id: 'vba',         name: 'VBA macro',         ext: '.bas/.docm',   opsec: 'low',  notes: 'Office macro. MOTW friction post-2022.',                 loader: 'DocxMacro' },
  { id: 'msbuild',     name: 'MSBuild project',   ext: '.csproj',      opsec: 'high', notes: 'Inline task XML via trusted MS-signed binary.',          loader: 'MsBuild' },
  { id: 'installutil', name: 'InstallUtil',       ext: '.dll',         opsec: 'med',  notes: 'Uninstall method abuse via signed .NET installer.',       loader: 'InstallUtil' },
  { id: 'shellcode',   name: 'Raw shellcode',     ext: '.bin',         opsec: 'n/a',  notes: 'Position-independent blob for your own loader.',         loader: 'Binary' },
]

const OPSEC_COLOR: Record<string, string> = {
  high: 'var(--ok)', med: 'var(--warn)', low: 'var(--danger)', 'n/a': 'var(--ink-muted)',
}

const LOLBIN_ROADMAP = ['regsvr32', 'mshta', 'rundll32', 'regasm', 'cmstp', 'msiexec', 'wmic']

interface Props {
  loaderType:         LoaderType
  onLoaderTypeChange: (t: LoaderType) => void
  encryption:         Encryption
  onEncryptionChange: (e: Encryption) => void
}

export default function OutputSection({ loaderType, onLoaderTypeChange, encryption, onEncryptionChange }: Props) {
  return (
    <section id="section-output" className="space-y-4">
      <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        04 — Output
      </h2>

      {/* Format grid */}
      <div className="grid grid-cols-2 gap-2">
        {FORMATS.map(f => {
          return (
            <button
              key={f.id}
              type="button"
              role="radio"
              aria-checked={loaderType === f.loader}
              data-testid={`format-${f.id}`}
              onClick={() => onLoaderTypeChange(f.loader)}
              className="text-left rounded-xl p-3 transition"
              style={{
                border: `1px solid ${loaderType === f.loader ? 'var(--blue-500)' : 'var(--border)'}`,
                backgroundColor: loaderType === f.loader ? 'var(--blue-alpha)' : 'var(--surface)',
              }}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium" style={{ color: 'var(--ink)' }}>{f.name}</span>
                <span className="text-[10px] font-mono" style={{ color: OPSEC_COLOR[f.opsec] }}>
                  {f.opsec}
                </span>
              </div>
              <div className="text-[10px] font-mono" style={{ color: 'var(--ink-muted)' }}>{f.ext}</div>
              <div className="text-xs mt-1" style={{ color: 'var(--ink-muted)' }}>{f.notes}</div>
            </button>
          )
        })}
      </div>

      {/* LOLBIN roadmap chips */}
      <div>
        <span className="text-xs mr-2" style={{ color: 'var(--ink-muted)' }}>Roadmap:</span>
        {LOLBIN_ROADMAP.map(l => (
          <span key={l} className="inline-block mr-1 mb-1 text-[10px] px-1.5 py-0.5 rounded" style={{ border: '1px solid var(--border)', color: 'var(--ink-muted)' }}>
            {l}
          </span>
        ))}
      </div>
    </section>
  )
}
