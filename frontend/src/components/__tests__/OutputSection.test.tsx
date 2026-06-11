import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import OutputSection from '../OutputSection'

const defaultProps = {
  loaderType: 'Binary' as const,
  onLoaderTypeChange: vi.fn(),
  encryption: 'Aes256' as const,
  onEncryptionChange: vi.fn(),
  appDomainConfig: {},
  onAppDomainConfigChange: vi.fn(),
}

describe('OutputSection', () => {
  it('renders 8 format cards', () => {
    render(React.createElement(OutputSection, { ...defaultProps }))
    expect(screen.getAllByRole('radio')).toHaveLength(8)
  })

  it('marks selected format as active', () => {
    render(React.createElement(OutputSection, { ...defaultProps, loaderType: 'Wsf' }))
    const wsfCard = screen.getByTestId('format-wsf')
    expect(wsfCard).toHaveAttribute('aria-checked', 'true')
  })

  it('calls onLoaderTypeChange on card click', () => {
    const onChange = vi.fn()
    render(React.createElement(OutputSection, { ...defaultProps, onLoaderTypeChange: onChange }))
    fireEvent.click(screen.getByTestId('format-dll'))
    expect(onChange).toHaveBeenCalledWith('Dll')
  })

  it('shows AppDomainConfig when loaderType is AppDomain', () => {
    render(React.createElement(OutputSection, { ...defaultProps, loaderType: 'AppDomain' }))
    expect(screen.getByText('CLR Version')).toBeInTheDocument()
  })

  it('does not show AppDomainConfig when loaderType is not AppDomain', () => {
    render(React.createElement(OutputSection, { ...defaultProps, loaderType: 'Binary' }))
    expect(screen.queryByText('CLR Version')).not.toBeInTheDocument()
  })
})
