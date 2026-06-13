import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Feature, Encryption, LoaderType, GenerateRequest, AppDomainReq, StagedReq, generate, appdomainConfigFilename } from '../api/generate'
import { StagePayload, listStages, uploadStage, deleteStage, rotateToken } from '../api/stage'
import { useJobSocket } from '../hooks/useJobSocket'
import Header, { StepId } from '../components/Header'
import PayloadSection from '../components/PayloadSection'
import StageTransferSection from '../components/StageTransferSection'
import EvasionSection from '../components/EvasionSection'
import OutputSection from '../components/OutputSection'
import BuildConsole, { LogLine, BuildStatus } from '../components/BuildConsole'
import { PROFILES, OUTPUT_FORMATS, techsToBackend } from '../data/designData'

export default function GeneratorPage() {
  useNavigate()

  const [mode, setMode] = useState<'stageless' | 'staged'>('stageless')
  const [shellcodeHex, setShellcodeHex] = useState('')
  const [binFilename, setBinFilename]   = useState<string | null>(null)
  const [stages, setStages] = useState<StagePayload[]>([])
  const [tokens, setTokens] = useState<Record<string, string>>({})
  const [activeStagePid, setActiveStagePid] = useState<string | null>(null)

  const [profile, setProfile]    = useState<'stealth' | 'balanced' | 'aggressive'>('stealth')
  const [enabled, setEnabled]    = useState<Set<string>>(() => new Set(PROFILES[0].techIds))
  const [formatId, setFormatId]  = useState<string>('exe')
  const [loaderType, setLoaderType] = useState<LoaderType>('Binary')
  const [appDomainConfig, setAppDomainConfig] = useState<AppDomainReq>({})

  const [jobId, setJobId]             = useState<string | null>(null)
  const [logs, setLogs]               = useState<LogLine[]>([])
  const [buildStatus, setBuildStatus] = useState<BuildStatus>('idle')
  const [artifactId, setArtifactId]   = useState<string | null>(null)
  const [configXml, setConfigXml]     = useState<string | null>(null)
  const [activeStep, setActiveStep]   = useState<StepId>('payload')

  // Switching profile populates enabled techs with that profile's defaults.
  useEffect(() => {
    const p = PROFILES.find(x => x.id === profile)
    if (p) setEnabled(new Set(p.techIds))
  }, [profile])

  // Hosts (auto-detect current host, override via localStorage / Settings).
  const currentHost = typeof window !== 'undefined' ? window.location.host : 'localhost:8090'
  const pickHost = (k: string) => {
    const v = localStorage.getItem(k)
    return !v || v === 'localhost:8080' ? currentHost : v
  }
  const stageHost = pickHost('defcrow_stage_host')
  const smugHost  = pickHost('defcrow_smug_host')

  useEffect(() => {
    listStages().then(s => {
      setStages(s)
      if (s.length > 0 && !activeStagePid) setActiveStagePid(s[0].pid)
    }).catch(() => {})
  }, [])

  const { status } = useJobSocket(jobId)
  useEffect(() => {
    if (!status) return
    const ts = new Date().toISOString().slice(11, 19)
    const tag = status.status === 'error' ? 'err' : status.status === 'done' ? 'ok' : 'info'
    setLogs(prev => [...prev, { ts, tag, msg: status.msg ?? status.status }])
    if (status.status === 'done') {
      setBuildStatus('done')
      if (status.download_id) setArtifactId(status.download_id)
      if (status.config_xml)  setConfigXml(status.config_xml)
    } else if (status.status === 'error') {
      setBuildStatus('error')
    }
  }, [status])

  // Scroll-into-view when step changes.
  useEffect(() => {
    const el = document.getElementById(activeStep)
    if (el) {
      const container = document.querySelector('.main-col') as HTMLElement | null
      if (container) {
        container.scrollTo({ top: el.offsetTop - 12, behavior: 'smooth' })
      } else {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }
    }
  }, [activeStep])

  function handleFileUpload(file: File) {
    setBinFilename(file.name)
    const reader = new FileReader()
    reader.onload = ev => {
      const buf   = ev.target?.result as ArrayBuffer
      const bytes = new Uint8Array(buf)
      setShellcodeHex(Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''))
    }
    reader.readAsArrayBuffer(file)
  }

  async function handleStageUpload(file: File) {
    try {
      const res = await uploadStage(file)
      setStages(prev => [...prev, { pid: res.pid, name: res.name, size: res.size, arch: 'x64', created_at: '' }])
      setTokens(prev => ({ ...prev, [res.pid]: res.jwt }))
      setActiveStagePid(res.pid)
    } catch {/* ignore */}
  }
  async function handleStageDelete(pid: string) {
    await deleteStage(pid).catch(() => {})
    setStages(prev => prev.filter(s => s.pid !== pid))
    setTokens(prev => { const n = { ...prev }; delete n[pid]; return n })
  }
  async function handleRotate(pid: string) {
    try {
      const res = await rotateToken(pid)
      setTokens(prev => ({ ...prev, [pid]: res.jwt }))
    } catch {/* ignore */}
  }

  function toggleTech(id: string) {
    setEnabled(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  async function handleForge() {
    setBuildStatus('building')
    setLogs([])
    setJobId(null)
    setArtifactId(null)
    setConfigXml(null)
    try {
      const { features, encryption } = techsToBackend(enabled)

      let stagedReq: StagedReq | undefined
      if (mode === 'staged') {
        const pid = activeStagePid ?? stages[0]?.pid
        const jwt = pid ? tokens[pid] : undefined
        if (!pid || !jwt) {
          setBuildStatus('error')
          setLogs(prev => [...prev, { ts: new Date().toISOString().slice(11, 19), tag: 'err', msg: 'No staged payload selected — upload first' }])
          return
        }
        stagedReq = {
          pid, jwt,
          host: stageHost,
          scheme: stageHost.includes('localhost') || stageHost.startsWith('127.') ? 'http' : 'https',
        }
      }

      const req: GenerateRequest = {
        loader_type:   loaderType,
        features:      mode === 'staged' && !features.includes('Staged' as Feature)
                         ? [...features, 'Staged' as Feature]
                         : features,
        encryption,
        shellcode_hex: mode === 'staged' ? '' : shellcodeHex.replace(/\s+/g, ''),
        key_hex: '',
        iv_hex:  '',
        appdomain_config: loaderType === 'AppDomain' ? {
          clr_version: appDomainConfig.clr_version || undefined,
          net_version: appDomainConfig.net_version || undefined,
          host_binary: appDomainConfig.host_binary || undefined,
        } : undefined,
        staged: stagedReq,
      }
      const { job_id } = await generate(req)
      setJobId(job_id)
    } catch {
      setBuildStatus('error')
      setLogs(prev => [...prev, { ts: new Date().toISOString().slice(11, 19), tag: 'err', msg: 'Generation failed' }])
    }
  }

  const canForge = mode === 'stageless'
    ? shellcodeHex.length > 0
    : stages.length > 0 && (activeStagePid ? !!tokens[activeStagePid] : !!tokens[stages[0]?.pid ?? ''])

  const EXT_BY_LOADER: Record<LoaderType, string> = {
    Binary: 'exe', Dll: 'dll', Injector: 'exe', Rundll32: 'dll',
    AppDomain: 'dll', InstallUtil: 'dll',
    Wsf: 'wsf', Hta: 'hta', Regsvr32Sct: 'sct', MsBuild: 'csproj',
    Cmstp: 'inf', WmicXsl: 'xsl',
    DocxMacro: 'bas', XlsxMacro: 'bas',
  }
  const artifactName = artifactId ? `loader_${artifactId.slice(0, 8)}.${EXT_BY_LOADER[loaderType]}` : null

  const summary = useMemo(() => {
    const fmt = OUTPUT_FORMATS.find(f => f.id === formatId)
    return `${mode} · ${enabled.size} tech · ${fmt?.name || '—'} · ${profile}`
  }, [mode, enabled.size, formatId, profile])

  return (
    <div className="app">
      <Header active={activeStep} setActive={setActiveStep} mode={mode}/>

      <div className="workspace">
        <div className="main-col">
          <PayloadSection
            mode={mode} setMode={setMode}
            shellcodeHex={shellcodeHex} setShellcodeHex={setShellcodeHex}
            binFilename={binFilename} setBinFilename={setBinFilename}
            stages={stages}
            activeStagePid={activeStagePid}
            setActiveStagePid={setActiveStagePid}
            onFileUpload={handleFileUpload}
            onStageUpload={handleStageUpload}
            onStageDelete={handleStageDelete}
          />

          {mode === 'staged' && (
            <StageTransferSection
              stages={stages}
              tokens={tokens}
              stageHost={stageHost}
              onRotate={handleRotate}
              selectedPid={activeStagePid}
              onSelect={setActiveStagePid}
            />
          )}

          <EvasionSection
            profile={profile} setProfile={setProfile}
            enabled={enabled} toggleTech={toggleTech}
          />

          <OutputSection
            formatId={formatId} setFormatId={setFormatId}
            loaderType={loaderType} setLoaderType={setLoaderType}
            appDomainConfig={appDomainConfig}
            onAppDomainConfigChange={setAppDomainConfig}
          />
        </div>

        <aside className="right-col">
          <BuildConsole
            logs={logs}
            status={buildStatus}
            canForge={canForge}
            onForge={handleForge}
            onClear={() => { setLogs([]); setBuildStatus('idle'); setArtifactId(null); setConfigXml(null) }}
            artifactId={artifactId}
            artifactName={artifactName}
            smugHost={smugHost}
            configXml={configXml}
            configFilename={appdomainConfigFilename(appDomainConfig.host_binary)}
            summary={summary}
          />
        </aside>
      </div>

      <footer className="footer">
        <span>defcrow</span>
        <span className="sep">·</span>
        <span>engine v0.5.0</span>
        <span className="sep">·</span>
        <span>build 2026.06</span>
        <span className="lic">For authorized red-team engagements and security research only.</span>
      </footer>
    </div>
  )
}
