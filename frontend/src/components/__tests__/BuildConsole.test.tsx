import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import BuildConsole from '../BuildConsole'

const defaultProps = {
  logs:         [],
  status:       'idle' as const,
  canForge:     true,
  onForge:      vi.fn(),
  artifactId:   null,
  artifactName: null,
  smugHost:     'localhost:8080',
}

describe('BuildConsole', () => {
  it('renders Forge button when idle', () => {
    render(React.createElement(BuildConsole, defaultProps))
    expect(screen.getByRole('button', { name: /forge/i })).toBeInTheDocument()
  })

  it('disables Forge button when canForge is false', () => {
    render(React.createElement(BuildConsole, { ...defaultProps, canForge: false }))
    expect(screen.getByRole('button', { name: /forge/i })).toBeDisabled()
  })

  it('shows log lines when provided', () => {
    render(React.createElement(BuildConsole, {
      ...defaultProps,
      logs: [{ ts: '12:00:00', tag: 'info', msg: 'compiling loader' }],
    }))
    expect(screen.getByText(/compiling loader/)).toBeInTheDocument()
  })

  it('shows building status badge', () => {
    render(React.createElement(BuildConsole, { ...defaultProps, status: 'building' }))
    expect(screen.getByText(/Building/i)).toBeInTheDocument()
  })
})
