import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import OpsecFeatures from '../OpsecFeatures'

describe('OpsecFeatures', () => {
  it('renders all 15 feature toggles', () => {
    render(React.createElement(OpsecFeatures, { selected: [], onChange: vi.fn() }))
    expect(screen.getAllByRole('switch')).toHaveLength(15)
  })
  it('shows selected features as checked', () => {
    render(React.createElement(OpsecFeatures, { selected: ['AmsiHwbp', 'EtwHwbp'], onChange: vi.fn() }))
    const amsi = screen.getByTestId('toggle-AmsiHwbp')
    expect(amsi).toHaveAttribute('data-state', 'checked')
  })
  it('calls onChange with new set when toggled', () => {
    const onChange = vi.fn()
    render(React.createElement(OpsecFeatures, { selected: [], onChange }))
    fireEvent.click(screen.getByTestId('toggle-AmsiHwbp'))
    expect(onChange).toHaveBeenCalledWith(expect.arrayContaining(['AmsiHwbp']))
  })
})
