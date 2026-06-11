import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import React from 'react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../../store/auth'
import SettingsPage from '../SettingsPage'

const Wrapper = ({ children }: { children: React.ReactNode }) =>
  React.createElement(MemoryRouter, null, React.createElement(AuthProvider, null, children))

describe('SettingsPage', () => {
  it('renders Settings heading', () => {
    render(React.createElement(SettingsPage), { wrapper: Wrapper })
    expect(screen.getByText(/Settings/i)).toBeInTheDocument()
  })

  it('renders Stage host input', () => {
    render(React.createElement(SettingsPage), { wrapper: Wrapper })
    expect(screen.getByLabelText(/Stage host/i)).toBeInTheDocument()
  })

  it('saves stage host to localStorage on save', () => {
    render(React.createElement(SettingsPage), { wrapper: Wrapper })
    const input = screen.getByLabelText(/Stage host/i)
    fireEvent.change(input, { target: { value: 'c2.example.com' } })
    fireEvent.click(screen.getByRole('button', { name: /Save/i }))
    expect(localStorage.getItem('defcrow_stage_host')).toBe('c2.example.com')
  })
})
