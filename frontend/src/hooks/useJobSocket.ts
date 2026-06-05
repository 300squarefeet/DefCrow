import { useEffect, useRef, useState } from 'react'

export interface JobStatus {
  status: 'queued' | 'building' | 'done' | 'error'
  progress?: number; msg?: string; download_id?: string
}

export function useJobSocket(jobId: string | null) {
  const [status, setStatus] = useState<JobStatus | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  useEffect(() => {
    if (!jobId) return
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${window.location.host}/ws/jobs/${jobId}`)
    wsRef.current = ws
    ws.onmessage = (e) => { try { setStatus(JSON.parse(e.data) as JobStatus) } catch {} }
    ws.onerror = () => setStatus({ status: 'error', msg: 'WebSocket connection failed' })
    return () => { ws.close(); wsRef.current = null }
  }, [jobId])
  return { status }
}
