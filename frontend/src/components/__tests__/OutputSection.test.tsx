import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import OutputSection from '../OutputSection'

describe('OutputSection', () => {
  it('renders 8 format cards', () => {
    render(React.createElement(OutputSection, { loaderType: 'Binary', onLoaderTypeChange: vi.fn(), encryption: 'Aes256', onEncryptionChange: vi.fn() }))
    expect(screen.getAllByRole('radio')).toHaveLength(8)
  })

  it('marks selected format as active', () => {
    render(React.createElement(OutputSection, { loaderType: 'Wsf', onLoaderTypeChange: vi.fn(), encryption: 'Aes256', onEncryptionChange: vi.fn() }))
    const wsfCard = screen.getByTestId('format-wsf')
    expect(wsfCard).toHaveAttribute('aria-checked', 'true')
  })

  it('calls onLoaderTypeChange on card click', () => {
    const onChange = vi.fn()
    render(React.createElement(OutputSection, { loaderType: 'Binary', onLoaderTypeChange: onChange, encryption: 'Aes256', onEncryptionChange: vi.fn() }))
    fireEvent.click(screen.getByTestId('format-dll'))
    expect(onChange).toHaveBeenCalledWith('Dll')
  })
})
