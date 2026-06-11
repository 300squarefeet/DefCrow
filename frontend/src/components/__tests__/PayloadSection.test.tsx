import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import PayloadSection from '../PayloadSection'

const defaultProps = {
  mode: 'stageless' as const,
  onModeChange: vi.fn(),
  shellcodeHex: '',
  onShellcodeHexChange: vi.fn(),
  binFilename: null,
  stages: [],
  onFileUpload: vi.fn(),
  onStageUpload: vi.fn(),
  onStageDelete: vi.fn(),
}

describe('PayloadSection', () => {
  it('renders mode selector cards', () => {
    render(React.createElement(PayloadSection, defaultProps))
    expect(screen.getByText(/Stageless/i)).toBeInTheDocument()
    expect(screen.getByText(/Staged/i)).toBeInTheDocument()
  })

  it('shows file upload zone in stageless mode', () => {
    render(React.createElement(PayloadSection, defaultProps))
    expect(screen.getByText(/Upload .bin/i)).toBeInTheDocument()
  })

  it('calls onModeChange when staged mode card is clicked', () => {
    const onModeChange = vi.fn()
    render(React.createElement(PayloadSection, { ...defaultProps, onModeChange }))
    fireEvent.click(screen.getByText(/Staged/i))
    expect(onModeChange).toHaveBeenCalledWith('staged')
  })

  it('shows staged list when mode is staged', () => {
    render(React.createElement(PayloadSection, {
      ...defaultProps,
      mode: 'staged',
      stages: [{ pid: 'abc123', name: 'shell.bin', size: 512, arch: 'x64', created_at: '0' }],
    }))
    expect(screen.getByText(/abc123/)).toBeInTheDocument()
    expect(screen.getByText(/shell.bin/)).toBeInTheDocument()
  })
})
