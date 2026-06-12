import { Feature, ALL_FEATURES } from '../api/generate'

const FEATURE_META: Record<Feature, { label: string; desc: string; category: string }> = {
  DirectSyscall:    { label: 'Indirect Syscalls',        desc: 'SSN resolved at runtime, trampoline via ntdll stub', category: 'Evasion' },
  UnhookDisk:       { label: 'NTDLL Unhook (Disk)',       desc: 'Reload clean ntdll from disk, overwrite hooked .text', category: 'Evasion' },
  UnhookKnownDlls:  { label: 'NTDLL Unhook (KnownDLLs)', desc: 'Map ntdll from KnownDLLs', category: 'Evasion' },
  ModuleStomp:      { label: 'Module Stomping',           desc: 'Shellcode in legit DLL .text — MEM_IMAGE not MEM_PRIVATE', category: 'Evasion' },
  SleepEncrypt:     { label: 'Sleep Masking (Ekko)',       desc: 'Full PE XOR-encrypted during sleep via TimerQueueTimer', category: 'Evasion' },
  StackSpoof:       { label: 'Stack Spoofing',            desc: 'Synthetic return addresses from ntdll/kernel32', category: 'Evasion' },
  SandboxDomain:    { label: 'Domain Check',              desc: 'Exit if not domain-joined via NetGetJoinInformation', category: 'Sandbox' },
  SandboxUser:      { label: 'User / Uptime Check',       desc: 'Exit if mouse static, RAM < 4GB, uptime < 5 min', category: 'Sandbox' },
  PpidSpoof:        { label: 'PPID Spoofing',             desc: 'Parent process via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS', category: 'Injection' },
  AmsiHwbp:         { label: 'AMSI Bypass (HW BP)',       desc: 'DR0=AmsiScanBuffer, VEH sets Rax=0 — zero memory IOC', category: 'Bypass' },
  EtwHwbp:          { label: 'ETW Bypass (HW BP)',        desc: 'DR1=EtwEventWrite, VEH suppresses event — zero memory IOC', category: 'Bypass' },
  PeSpoofing:       { label: 'PE Metadata Spoof',         desc: 'Version info cloned from legitimate binary', category: 'Misc' },
  Staged:           { label: 'Staged Payload',            desc: 'Shellcode fetched from remote URL at runtime', category: 'Delivery' },
  AppDomain:        { label: 'AppDomain Injection',       desc: 'ICLRRuntimeHost2 + .config AppDomainManager hijacking', category: 'Injection' },
  ThreadlessInject: { label: 'Threadless Injection',      desc: 'TpAllocWork callback — no CreateRemoteThread', category: 'Injection' },
  Compress:         { label: 'Compress Payload',          desc: 'Deflate shellcode before XOR-encrypt; C# loaders decompress via System.IO.Compression', category: 'Delivery' },
}

const CATEGORIES = ['Evasion', 'Bypass', 'Injection', 'Sandbox', 'Delivery', 'Misc']

interface Props { selected: Feature[]; onChange: (f: Feature[]) => void }

export default function OpsecFeatures({ selected, onChange }: Props) {
  function toggle(f: Feature) {
    onChange(selected.includes(f) ? selected.filter((x) => x !== f) : [...selected, f])
  }
  return (
    <div className="space-y-5">
      {CATEGORIES.map((cat) => {
        const features = ALL_FEATURES.filter((f) => FEATURE_META[f].category === cat)
        if (!features.length) return null
        return (
          <div key={cat}>
            <p className="text-xs uppercase tracking-widest mb-2" style={{ color: '#64748b' }}>{cat}</p>
            <div className="grid grid-cols-1 gap-2" style={{ gridTemplateColumns: 'repeat(2, 1fr)' }}>
              {features.map((f) => {
                const { label, desc } = FEATURE_META[f]
                const enabled = selected.includes(f)
                return (
                  <button key={f} type="button"
                    role="switch" aria-checked={enabled}
                    data-state={enabled ? 'checked' : 'unchecked'}
                    data-testid={`toggle-${f}`}
                    onClick={() => toggle(f)}
                    className="text-left rounded-xl p-3 transition"
                    style={{
                      border: `1px solid ${enabled ? '#7c3aed' : '#1e1e2e'}`,
                      backgroundColor: enabled ? 'rgba(124,58,237,0.1)' : '#12121a',
                    }}
                  >
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: enabled ? '#7c3aed' : '#1e1e2e' }} />
                      <span className="text-sm font-medium" style={{ color: '#e2e8f0' }}>{label}</span>
                    </div>
                    <p className="text-xs mt-1 ml-4 leading-relaxed" style={{ color: '#64748b' }}>{desc}</p>
                  </button>
                )
              })}
            </div>
          </div>
        )
      })}
    </div>
  )
}
