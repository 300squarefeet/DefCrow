import { PROFILES, TECH_GROUPS } from '../data/designData'

interface Props {
  profile:    'stealth' | 'balanced' | 'aggressive'
  setProfile: (p: 'stealth' | 'balanced' | 'aggressive') => void
  enabled:    Set<string>
  toggleTech: (id: string) => void
}

export default function EvasionSection({ profile, setProfile, enabled, toggleTech }: Props) {
  return (
    <section className="section" id="evasion">
      <div className="section-label">
        <span className="num">03</span>
        <span className="name">Evasion profile</span>
        <span className="meta">Best-in-class techniques only</span>
      </div>

      <div className="profile-grid">
        {PROFILES.map(p => (
          <div
            key={p.id}
            className={'profile' + (profile === p.id ? ' active' : '')}
            onClick={() => setProfile(p.id)}
          >
            <div className="profile-head">
              <div className="profile-name">{p.name}</div>
              <span className="profile-score-tag">{p.score}/100</span>
            </div>
            <div className="profile-tag">{p.tagline}</div>
            <div className="profile-bar"><div className="profile-bar-fill" style={{ width: p.score + '%' }}/></div>
            <div className="profile-foot">
              <span>{p.techIds.length} techniques</span>
              <span>{p.id === 'stealth' ? '~40s build' : p.id === 'balanced' ? '~18s build' : '~8s build'}</span>
            </div>
          </div>
        ))}
      </div>

      {TECH_GROUPS.map(g => (
        <div className="tech-group" key={g.id}>
          <div className="tech-group-title">
            <span className="tg-name">{g.name}</span>
            <span className="count">
              <span className="on-num">{g.items.filter(t => enabled.has(t.id)).length}</span>/{g.items.length} enabled
            </span>
          </div>
          <div className="tech-list">
            {g.items.map(t => {
              const on = enabled.has(t.id)
              return (
                <div key={t.id} className={'tech' + (on ? ' on' : '')} onClick={() => toggleTech(t.id)}>
                  <div className="tech-check"/>
                  <div className="tech-body">
                    <div className="tech-name">
                      {t.name} <span className={'risk ' + t.risk}>{t.risk}</span>
                    </div>
                    <div className="tech-desc">{t.desc}</div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </section>
  )
}
