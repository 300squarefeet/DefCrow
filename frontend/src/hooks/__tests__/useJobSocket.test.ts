import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { useJobSocket } from '../useJobSocket'

class MockWS {
  onmessage: ((e: MessageEvent) => void) | null = null
  onclose: (() => void) | null = null
  onerror: ((e: Event) => void) | null = null
  close = vi.fn()
  emit(data: object) { this.onmessage?.({ data: JSON.stringify(data) } as MessageEvent) }
}

let mockWs: MockWS
vi.stubGlobal('WebSocket', vi.fn(() => { mockWs = new MockWS(); return mockWs }))

describe('useJobSocket', () => {
  it('starts with null status', () => {
    const { result } = renderHook(() => useJobSocket('job-123'))
    expect(result.current.status).toBeNull()
  })
  it('updates status on message', () => {
    const { result } = renderHook(() => useJobSocket('job-123'))
    act(() => { mockWs.emit({ status: 'building', progress: 40, msg: 'Compiling...' }) })
    expect(result.current.status).toMatchObject({ status: 'building', progress: 40 })
  })
  it('closes socket on unmount', () => {
    const { unmount } = renderHook(() => useJobSocket('job-123'))
    unmount()
    expect(mockWs.close).toHaveBeenCalled()
  })
  it('does not connect if jobId is null', () => {
    const createWS = vi.fn()
    vi.stubGlobal('WebSocket', createWS)
    renderHook(() => useJobSocket(null))
    expect(createWS).not.toHaveBeenCalled()
  })
})
