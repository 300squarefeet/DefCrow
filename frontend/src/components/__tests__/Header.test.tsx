import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../../store/auth'
import Header from '../Header'

const Wrapper = ({ children }: { children: React.ReactNode }) =>
  React.createElement(MemoryRouter, null, React.createElement(AuthProvider, null, children))

describe('Header', () => {
  it('renders DefCrow brand name', () => {
    render(
      React.createElement(Header, { currentStep: 1, showStageTransfer: false, onStepClick: vi.fn() }),
      { wrapper: Wrapper }
    )
    expect(screen.getByText('DefCrow')).toBeInTheDocument()
  })

  it('renders 4 step buttons when showStageTransfer is false', () => {
    render(
      React.createElement(Header, { currentStep: 1, showStageTransfer: false, onStepClick: vi.fn() }),
      { wrapper: Wrapper }
    )
    const steps = screen.getAllByRole('button').filter(b => b.textContent?.includes('0'))
    expect(steps).toHaveLength(4)
  })

  it('renders 5 step buttons when showStageTransfer is true', () => {
    render(
      React.createElement(Header, { currentStep: 1, showStageTransfer: true, onStepClick: vi.fn() }),
      { wrapper: Wrapper }
    )
    const steps = screen.getAllByRole('button').filter(b => b.textContent?.includes('0'))
    expect(steps).toHaveLength(5)
  })

  it('calls onStepClick with step id when step button is clicked', () => {
    const onStepClick = vi.fn()
    render(
      React.createElement(Header, { currentStep: 1, showStageTransfer: false, onStepClick }),
      { wrapper: Wrapper }
    )
    fireEvent.click(screen.getByText(/03 Evasion/))
    expect(onStepClick).toHaveBeenCalledWith(3)
  })
})
