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

  it('shows config XML textarea when configXml prop is set and status is done', () => {
    render(React.createElement(BuildConsole, {
      ...defaultProps,
      status:      'done' as const,
      artifactId:  'abc123',
      artifactName: 'loader_abc123.exe',
      configXml:   '<?xml version="1.0"?><configuration></configuration>',
    }))
    expect(screen.getByText(/MSBuild\.exe\.config/i)).toBeInTheDocument()
    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })

  it('does not show config section when configXml is null', () => {
    render(React.createElement(BuildConsole, {
      ...defaultProps,
      status:      'done' as const,
      artifactId:  'abc123',
      artifactName: 'loader_abc123.exe',
      configXml:   null,
    }))
    expect(screen.queryByText(/MSBuild\.exe\.config/i)).not.toBeInTheDocument()
  })
})
