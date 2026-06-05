import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import React from 'react'
import { MemoryRouter } from 'react-router-dom'
import LoginPage from '../LoginPage'
import { AuthProvider } from '../../store/auth'
import * as authApi from '../../api/auth'

const Wrapper = ({ children }: { children: React.ReactNode }) =>
  React.createElement(MemoryRouter, null, React.createElement(AuthProvider, null, children))

describe('LoginPage', () => {
  it('renders username and password fields', () => {
    render(React.createElement(LoginPage), { wrapper: Wrapper })
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
  })
  it('shows error on invalid credentials', async () => {
    vi.spyOn(authApi, 'login').mockRejectedValue({ response: { status: 401 } })
    render(React.createElement(LoginPage), { wrapper: Wrapper })
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'wrong' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument())
  })
  it('disables submit button while loading', async () => {
    vi.spyOn(authApi, 'login').mockImplementation(() => new Promise(() => {}))
    render(React.createElement(LoginPage), { wrapper: Wrapper })
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'password' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => expect(screen.getByRole('button', { name: /signing in/i })).toBeDisabled())
  })
})
