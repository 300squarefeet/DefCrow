import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../../store/auth'
import GeneratorPage from '../GeneratorPage'

vi.mock('../../api/generate', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/generate')>()
  return { ...actual, generate: vi.fn().mockResolvedValue({ job_id: 'test-job' }) }
})

vi.mock('../../api/stage', () => ({
  listStages: vi.fn().mockResolvedValue([]),
  uploadStage: vi.fn(),
  deleteStage: vi.fn(),
  rotateToken: vi.fn(),
}))

const Wrapper = ({ children }: { children: React.ReactNode }) =>
  React.createElement(MemoryRouter, null, React.createElement(AuthProvider, null, children))

describe('GeneratorPage', () => {
  it('renders the header with DefCrow brand', () => {
    render(React.createElement(GeneratorPage), { wrapper: Wrapper })
    expect(screen.getByText('DefCrow')).toBeInTheDocument()
  })

  it('renders Payload section', () => {
    render(React.createElement(GeneratorPage), { wrapper: Wrapper })
    expect(screen.getByText(/01 — Payload/i)).toBeInTheDocument()
  })
})
