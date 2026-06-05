import { useParams, Link } from 'react-router-dom'
import { useJobSocket } from '../hooks/useJobSocket'

export default function JobStatusPage() {
  const { id } = useParams<{ id: string }>()
  const { status } = useJobSocket(id ?? null)
  return (
    <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: '#0a0a0f' }}>
      <div className="w-full max-w-lg rounded-2xl p-8 space-y-6" style={{ border: '1px solid #1e1e2e', backgroundColor: '#12121a' }}>
        <div className="text-center">
          <h1 className="text-xl font-bold" style={{ color: '#e2e8f0' }}>Build Job</h1>
          <p className="text-xs font-mono mt-1" style={{ color: '#64748b' }}>{id}</p>
        </div>
        {!status && (
          <div className="flex items-center gap-3 justify-center">
            <div className="w-4 h-4 rounded-full animate-pulse" style={{ backgroundColor: '#64748b' }} />
            <span className="text-sm" style={{ color: '#64748b' }}>Connecting…</span>
          </div>
        )}
        {status?.status === 'queued' && (
          <div className="flex items-center gap-3 justify-center">
            <div className="w-4 h-4 rounded-full animate-pulse" style={{ backgroundColor: '#fbbf24' }} />
            <span className="text-sm" style={{ color: '#fbbf24' }}>Queued</span>
          </div>
        )}
        {status?.status === 'building' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm" style={{ color: '#e2e8f0' }}>{status.msg}</span>
              <span className="text-sm font-mono" style={{ color: '#7c3aed' }}>{status.progress}%</span>
            </div>
            <div role="progressbar" aria-valuenow={status.progress} aria-valuemin={0} aria-valuemax={100}
              className="w-full h-2 rounded-full overflow-hidden" style={{ backgroundColor: '#1e1e2e' }}>
              <div className="h-full rounded-full transition-all duration-500"
                style={{ width: `${status.progress}%`, backgroundColor: '#7c3aed' }} />
            </div>
          </div>
        )}
        {status?.status === 'done' && (
          <div className="space-y-4 text-center">
            <div className="flex items-center gap-3 justify-center">
              <div className="w-4 h-4 rounded-full" style={{ backgroundColor: '#16a34a' }} />
              <span className="text-sm font-medium" style={{ color: '#16a34a' }}>Build complete</span>
            </div>
            <a href={`/api/download/${status.download_id}`} download role="link"
              className="inline-flex items-center gap-2 px-6 py-3 rounded-xl text-white font-medium text-sm transition"
              style={{ backgroundColor: '#16a34a' }}>
              Download Loader
            </a>
          </div>
        )}
        {status?.status === 'error' && (
          <div className="rounded-xl p-4" style={{ backgroundColor: 'rgba(127,0,0,0.2)', border: '1px solid #7f1d1d' }}>
            <p className="text-sm font-medium mb-2" style={{ color: '#dc2626' }}>Build Failed</p>
            <pre className="text-xs font-mono leading-relaxed whitespace-pre-wrap" style={{ color: '#64748b' }}>{status.msg}</pre>
          </div>
        )}
        <div className="text-center">
          <Link to="/" className="text-xs transition" style={{ color: '#64748b' }}>← Back to Generator</Link>
        </div>
      </div>
    </div>
  )
}
