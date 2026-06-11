import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import EvasionSection from '../EvasionSection'
import type { Feature, Encryption } from '../../api/generate'

const defaultProps = {
  features: [] as Feature[],
  encryption: 'Aes256' as Encryption,
  onFeaturesChange: vi.fn(),
  onEncryptionChange: vi.fn(),
}

describe('EvasionSection', () => {
  it('renders three profile cards', () => {
    render(React.createElement(EvasionSection, defaultProps))
    expect(screen.getByText('Stealth')).toBeInTheDocument()
    expect(screen.getByText('Balanced')).toBeInTheDocument()
    expect(screen.getByText('Aggressive')).toBeInTheDocument()
  })

  it('renders technique group headings', () => {
    render(React.createElement(EvasionSection, defaultProps))
    expect(screen.getByText(/Syscalls/i)).toBeInTheDocument()
    expect(screen.getByText(/Shellcode encryption/i)).toBeInTheDocument()
    expect(screen.getByText(/Anti-analysis/i)).toBeInTheDocument()
  })

  it('selecting Stealth profile calls onFeaturesChange with stealth features', () => {
    const onFeaturesChange = vi.fn()
    render(React.createElement(EvasionSection, { ...defaultProps, onFeaturesChange }))
    fireEvent.click(screen.getByText('Stealth'))
    expect(onFeaturesChange).toHaveBeenCalledWith(
      expect.arrayContaining(['DirectSyscall', 'AmsiHwbp', 'EtwHwbp', 'SleepEncrypt'])
    )
  })

  it('shows enabled count per group', () => {
    render(React.createElement(EvasionSection, {
      ...defaultProps,
      features: ['DirectSyscall' as Feature],
    }))
    expect(screen.getAllByText(/1\/\d+ enabled/).length).toBeGreaterThan(0)
  })
})
