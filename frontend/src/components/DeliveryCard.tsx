import { useState } from 'react'

const EXTENSIONS = ['.pdf', '.jpg', '.png', '.gif', '.iso', '.zip', '.svg', '.jpeg']

interface Props {
  artifactName: string
  stageHost:    string
}

export default function DeliveryCard({ artifactName, stageHost }: Props) {
  const [ext, setExt] = useState('.pdf')
  const baseName = artifactName.replace(/\.[^.]+$/, '')
  const fakeName = `${baseName}${ext}`
  const linkId   = Math.random().toString(36).slice(2, 10)

  return (
    <div className="rounded-xl p-4 space-y-3" style={{ border: '1px solid var(--border)', backgroundColor: 'var(--surface-2)' }}>
      <div className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--ink-muted)' }}>
        Delivery
      </div>

      {/* Extension picker */}
      <div className="flex flex-wrap gap-1">
        {EXTENSIONS.map(e => (
          <button
            key={e}
            type="button"
            onClick={() => setExt(e)}
            className="text-[10px] px-2 py-0.5 rounded font-mono transition"
            style={{
              border: `1px solid ${ext === e ? 'var(--blue-500)' : 'var(--border)'}`,
              backgroundColor: ext === e ? 'var(--blue-alpha)' : 'transparent',
              color: ext === e ? 'var(--blue-500)' : 'var(--ink-muted)',
            }}
          >
            {e}
          </button>
        ))}
      </div>

      {/* URL preview */}
      <div className="rounded-lg px-3 py-2 font-mono text-xs break-all" style={{ backgroundColor: 'var(--surface)', color: 'var(--ink-muted)' }}>
        https://{stageHost}/d/{linkId}/{fakeName}
      </div>

      <button
        type="button"
        className="w-full py-2 rounded-lg text-xs font-medium transition"
        style={{ backgroundColor: 'var(--blue-500)', color: '#fff' }}
        onClick={() => navigator.clipboard?.writeText(`https://${stageHost}/d/${linkId}/${fakeName}`)}
      >
        Copy link
      </button>
    </div>
  )
}
