import { LoaderType, AppDomainReq } from '../api/generate'
import { OUTPUT_FORMATS, LOLBIN_ROADMAP } from '../data/designData'
import AppDomainConfig from './AppDomainConfig'

interface Props {
  formatId:               string
  setFormatId:            (id: string) => void
  loaderType:             LoaderType
  setLoaderType:          (t: LoaderType) => void
  appDomainConfig:        AppDomainReq
  onAppDomainConfigChange: (c: AppDomainReq) => void
}

export default function OutputSection({
  formatId, setFormatId, setLoaderType,
  appDomainConfig, onAppDomainConfigChange,
}: Props) {
  return (
    <section className="section" id="output">
      <div className="section-label">
        <span className="num">04</span>
        <span className="name">Output format</span>
        <span className="meta">.exe · .dll · AppDomain · WSF · VBA · MSBuild · InstallUtil</span>
      </div>

      <div className="format-grid">
        {OUTPUT_FORMATS.map(f => (
          <div
            key={f.id}
            className={'format' + (formatId === f.id ? ' active' : '')}
            onClick={() => { setFormatId(f.id); setLoaderType(f.loader) }}
          >
            <div className="format-head">
              <div className="format-ico">{f.id.slice(0,3).toUpperCase()}</div>
              <div>
                <div className="format-name">{f.name}</div>
                <div className="format-ext">{f.ext}</div>
              </div>
            </div>
            <div className="format-notes">{f.notes}</div>
            <div className="format-foot">
              <span className={'risk opsec-' + f.opsec.replace('/', '')}>opsec: {f.opsec}</span>
            </div>
          </div>
        ))}
        <div className="format coming">
          <div className="format-head">
            <div className="format-ico">+</div>
            <div>
              <div className="format-name">All LOLBins</div>
              <div className="format-ext">roadmap</div>
            </div>
          </div>
          <div className="format-notes">regsvr32, mshta, rundll32, regasm, cmstp, msiexec…</div>
          <div className="format-foot"><span className="format-soon">Coming Q3</span></div>
        </div>
      </div>

      {formatId === 'appdomain' && (
        <div style={{ marginTop: 16 }}>
          <AppDomainConfig value={appDomainConfig} onChange={onAppDomainConfigChange}/>
        </div>
      )}

      <div style={{ marginTop: 22 }}>
        <div className="section-label" style={{ marginBottom: 12 }}>
          <span className="num">+</span>
          <span className="name">LOLBin roadmap</span>
        </div>
        <div className="lolbin-row">
          {LOLBIN_ROADMAP.map(b => <span key={b} className="lolbin-chip">{b}</span>)}
        </div>
      </div>
    </section>
  )
}
