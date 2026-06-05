import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import JobStatusPage from '../JobStatusPage'
import * as socketHook from '../../hooks/useJobSocket'

function wrap(element: React.ReactElement) {
  return (
    <MemoryRouter initialEntries={['/job/abc123']}>
      <Routes><Route path="/job/:id" element={element} /></Routes>
    </MemoryRouter>
  )
}

describe('JobStatusPage', () => {
  it('shows queued state', () => {
    vi.spyOn(socketHook, 'useJobSocket').mockReturnValue({ status: { status: 'queued' } })
    render(wrap(React.createElement(JobStatusPage)))
    expect(screen.getByText(/queued/i)).toBeInTheDocument()
  })
  it('shows progress bar while building', () => {
    vi.spyOn(socketHook, 'useJobSocket').mockReturnValue({ status: { status: 'building', progress: 40, msg: 'Compiling...' } })
    render(wrap(React.createElement(JobStatusPage)))
    expect(screen.getByText('Compiling...')).toBeInTheDocument()
    expect(screen.getByRole('progressbar')).toBeInTheDocument()
  })
  it('shows download button when done', () => {
    vi.spyOn(socketHook, 'useJobSocket').mockReturnValue({ status: { status: 'done', download_id: 'xyz789' } })
    render(wrap(React.createElement(JobStatusPage)))
    expect(screen.getByRole('link', { name: /download/i })).toBeInTheDocument()
  })
  it('shows error message on failure', () => {
    vi.spyOn(socketHook, 'useJobSocket').mockReturnValue({ status: { status: 'error', msg: 'rustc: linker not found' } })
    render(wrap(React.createElement(JobStatusPage)))
    expect(screen.getByText(/linker not found/i)).toBeInTheDocument()
  })
})
