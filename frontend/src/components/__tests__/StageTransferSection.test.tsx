import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import StageTransferSection from '../StageTransferSection'
import type { StagePayload } from '../../api/stage'

const STAGE: StagePayload = { pid: 'abc123def456', name: 'shell.bin', size: 512, arch: 'x64', created_at: '0' }

describe('StageTransferSection', () => {
  it('renders endpoint URL containing pid', () => {
    render(React.createElement(StageTransferSection, {
      stages: [STAGE],
      tokens: { 'abc123def456': 'hdr.pay.sig' },
      stageHost: 'c2.example.com',
      onRotate: vi.fn(),
    }))
    expect(screen.getByText(/abc123def456/)).toBeInTheDocument()
  })

  it('renders JWT segments', () => {
    render(React.createElement(StageTransferSection, {
      stages: [STAGE],
      tokens: { 'abc123def456': 'hdr.pay.sig' },
      stageHost: 'c2.example.com',
      onRotate: vi.fn(),
    }))
    expect(screen.getByText('hdr')).toBeInTheDocument()
    expect(screen.getByText('pay')).toBeInTheDocument()
    expect(screen.getByText('sig')).toBeInTheDocument()
  })
})
