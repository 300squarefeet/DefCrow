import { client } from './client'

export type LoaderType = 'Binary' | 'Dll' | 'AppDomain' | 'Injector'
export type Encryption  = 'Aes256' | 'Chacha20'

export const ALL_FEATURES = [
  'DirectSyscall', 'UnhookDisk', 'UnhookKnownDlls',
  'ModuleStomp',   'SleepEncrypt', 'StackSpoof',
  'SandboxDomain', 'SandboxUser',  'PpidSpoof',
  'AmsiHwbp',      'EtwHwbp',      'PeSpoofing',
  'Staged',        'AppDomain',     'ThreadlessInject',
] as const
export type Feature = typeof ALL_FEATURES[number]

export interface PeMetadataReq {
  company_name: string; file_description: string; product_name: string
  file_version: string; original_filename: string; legal_copyright: string
  sign: boolean; cert_pem?: string
}

export interface AppDomainReq {
  clr_version: string; net_version: string
  appdomain_type: string; target_assembly: string
}

export interface GenerateRequest {
  loader_type: LoaderType; features: Feature[]
  encryption: Encryption; shellcode_hex: string
  key_hex: string; iv_hex: string
  pe_config?: PeMetadataReq; appdomain_config?: AppDomainReq
}

export interface GenerateResponse { job_id: string }

export async function generate(req: GenerateRequest): Promise<GenerateResponse> {
  const { data } = await client.post<GenerateResponse>('/generate', req)
  return data
}
