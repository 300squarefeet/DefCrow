import { Feature, Encryption, PROFILE_FEATURES, PROFILE_ENCRYPTION, Profile } from '../api/generate'

interface TechItem { id: string; name: string; risk: 'low' | 'med' | 'high'; desc: string; feature?: Feature; encryption?: Encryption }
interface TechGroup { id: string; name: string; items: TechItem[] }

const TECH_GROUPS: TechGroup[] = [
  {
    id: 'syscalls', name: 'Syscalls & API resolution',
    items: [
      { id: 'indirect_syscalls', name: "Hell's Gate + SSN resolver", risk: 'low', desc: 'Resolve SSNs from clean NTDLL, jump through ntdll gadget.', feature: 'DirectSyscall' },
      { id: 'ntdll_unhook',      name: 'NTDLL unhook from \\KnownDlls',   risk: 'low', desc: 'Re-map fresh ntdll .text to overwrite inline hooks.',       feature: 'UnhookKnownDlls' },
    ],
  },
  {
    id: 'encryption', name: 'Shellcode encryption',
    items: [
      { id: 'aes_gcm_payload',  name: 'AES-256-GCM (recommended)', risk: 'low',  desc: 'Authenticated encryption, per-build key.',      encryption: 'Aes256' as Encryption },
      { id: 'chacha20_payload', name: 'ChaCha20-Poly1305',          risk: 'low',  desc: 'Fast auth encryption, no AES-NI required.', encryption: 'Chacha20' as Encryption },
    ],
  },
  {
    id: 'injection', name: 'Execution & injection',
    items: [
      { id: 'module_stomping', name: 'Module stomping',    risk: 'low', desc: 'Overwrite benign signed DLL .text. MEM_IMAGE not MEM_PRIVATE.', feature: 'ModuleStomp' },
      { id: 'ppid_spoof',      name: 'PPID spoofing',      risk: 'low', desc: 'Child appears to descend from explorer.exe.',                  feature: 'PpidSpoof' },
    ],
  },
  {
    id: 'memory', name: 'Memory & sleep',
    items: [
      { id: 'ekko_sleep',  name: 'Ekko sleep mask',       risk: 'low', desc: 'Encrypt heap + .text during sleep, restore on wake.', feature: 'SleepEncrypt' },
      { id: 'stack_spoof', name: 'Call stack spoofing',   risk: 'low', desc: 'Synthetic return addresses from ntdll/kernel32.',     feature: 'StackSpoof' },
    ],
  },
  {
    id: 'anti', name: 'Anti-analysis',
    items: [
      { id: 'amsi_hwbp', name: 'AMSI hardware-breakpoint bypass', risk: 'low', desc: 'DR0 breakpoint on AmsiScanBuffer — zero memory IOC.', feature: 'AmsiHwbp' },
      { id: 'etw_patch',  name: 'ETW-Ti patch',                   risk: 'low', desc: 'Neuter EtwEventWrite via byte patch.',                  feature: 'EtwHwbp' },
    ],
  },
]

const PROFILES: { id: Profile; name: string; score: number; tagline: string }[] = [
  { id: 'stealth',    name: 'Stealth',    score: 92, tagline: 'Maximum opsec. Slow, quiet, surgical.' },
  { id: 'balanced',   name: 'Balanced',   score: 76, tagline: 'Reasonable footprint, broad EDR coverage.' },
  { id: 'aggressive', name: 'Aggressive', score: 54, tagline: 'Loud but versatile.' },
]

const RISK_COLOR: Record<string, string> = { low: 'var(--ok)', med: 'var(--warn)', high: 'var(--danger)' }

interface Props {
  features:           Feature[]
  encryption:         Encryption
  onFeaturesChange:   (f: Feature[]) => void
  onEncryptionChange: (e: Encryption) => void
}

export default function EvasionSection({ features, encryption, onFeaturesChange, onEncryptionChange }: Props) {
  function isTechActive(item: TechItem): boolean {
    if (item.feature)    return features.includes(item.feature)
    if (item.encryption) return encryption === item.encryption
    return false
  }

  function toggleTech(item: TechItem) {
    if (item.feature) {
      onFeaturesChange(
        features.includes(item.feature)
          ? features.filter(f => f !== item.feature)
          : [...features, item.feature]
      )
    } else if (item.encryption) {
      onEncryptionChange(item.encryption)
    }
  }

  function applyProfile(p: Profile) {
    onFeaturesChange(PROFILE_FEATURES[p])
    onEncryptionChange(PROFILE_ENCRYPTION[p])
  }

  return (
    <section id="section-evasion" className="space-y-6">
      <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        03 — Evasion
      </h2>

      {/* Profile cards */}
      <div className="grid grid-cols-3 gap-3">
        {PROFILES.map(p => (
          <button
            key={p.id}
            type="button"
            onClick={() => applyProfile(p.id)}
            className="rounded-xl p-4 text-left transition"
            style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface)' }}
          >
            <div className="font-semibold text-sm" style={{ color: 'var(--ink)' }}>{p.name}</div>
            <div className="text-xs mt-1" style={{ color: 'var(--ink-muted)' }}>{p.tagline}</div>
            <div className="mt-3 flex items-center gap-2">
              <div className="h-1.5 flex-1 rounded-full" style={{ backgroundColor: 'var(--border)' }}>
                <div className="h-full rounded-full" style={{ width: `${p.score}%`, backgroundColor: 'var(--blue-500)' }} />
              </div>
              <span className="text-xs font-mono" style={{ color: 'var(--ink-muted)' }}>{p.score}/100</span>
            </div>
          </button>
        ))}
      </div>

      {/* Technique groups */}
      {TECH_GROUPS.map(group => {
        const activeCount = group.items.filter(isTechActive).length
        return (
          <div key={group.id}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium" style={{ color: 'var(--ink)' }}>{group.name}</span>
              <span className="text-xs font-mono" style={{ color: 'var(--ink-muted)' }}>
                {activeCount}/{group.items.length} enabled
              </span>
            </div>
            <div className="grid grid-cols-1 gap-2">
              {group.items.map(item => {
                const active = isTechActive(item)
                return (
                  <button
                    key={item.id}
                    type="button"
                    role="switch"
                    aria-checked={active}
                    onClick={() => toggleTech(item)}
                    className="text-left rounded-xl p-3 transition"
                    style={{
                      border: `1px solid ${active ? 'var(--blue-500)' : 'var(--border)'}`,
                      backgroundColor: active ? 'var(--blue-alpha)' : 'var(--surface)',
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full" style={{ backgroundColor: active ? 'var(--blue-500)' : 'var(--border)' }} />
                        <span className="text-sm font-medium" style={{ color: 'var(--ink)' }}>{item.name}</span>
                      </div>
                      <span className="text-[10px] px-1.5 py-0.5 rounded font-mono uppercase" style={{ color: RISK_COLOR[item.risk], border: `1px solid ${RISK_COLOR[item.risk]}` }}>
                        {item.risk}
                      </span>
                    </div>
                    <p className="text-xs mt-1 ml-4" style={{ color: 'var(--ink-muted)' }}>{item.desc}</p>
                  </button>
                )
              })}
            </div>
          </div>
        )
      })}
    </section>
  )
}
