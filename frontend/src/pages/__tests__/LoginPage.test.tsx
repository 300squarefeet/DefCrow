import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import React from 'react'
import { MemoryRouter } from 'react-router-dom'
import LoginPage from '../LoginPage'
import { AuthProvider } from '../../store/auth'
import * as authApi from '../../api/auth'

function wrap() {
  return (
    <MemoryRouter initialEntries={['/login']}>
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    </MemoryRouter>
  )
}

describe('LoginPage', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  it('renders the username step initially', () => {
    render(wrap())
    expect(screen.getByText(/sign in/i)).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/crow\.ops/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /request key/i })).toBeInTheDocument()
    expect(screen.queryByPlaceholderText(/abcd2345/i)).not.toBeInTheDocument()
  })

  it('transitions to key step after successful request-key call', async () => {
    const reqSpy = vi.spyOn(authApi, 'requestKey').mockResolvedValue({ delivered: true })
    const user = userEvent.setup()
    render(wrap())
    await user.type(screen.getByPlaceholderText(/crow\.ops/i), 'alice')
    await user.click(screen.getByRole('button', { name: /request key/i }))
    await waitFor(() => {
      expect(screen.getByText(/enter access key/i)).toBeInTheDocument()
    })
    expect(reqSpy).toHaveBeenCalledWith('alice')
    expect(screen.getByText(/key sent to discord/i)).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/abcd2345/i)).toBeInTheDocument()
    expect(screen.getByText(/operator:/i)).toBeInTheDocument()
  })

  it('shows error inline when key submit fails with 401', async () => {
    vi.spyOn(authApi, 'requestKey').mockResolvedValue({ delivered: true })
    const err = Object.assign(new Error('unauthorized'), { response: { status: 401 } })
    vi.spyOn(authApi, 'loginWithKey').mockRejectedValue(err)

    const user = userEvent.setup()
    render(wrap())
    await user.type(screen.getByPlaceholderText(/crow\.ops/i), 'alice')
    await user.click(screen.getByRole('button', { name: /request key/i }))
    await waitFor(() => screen.getByPlaceholderText(/abcd2345/i))
    await user.type(screen.getByPlaceholderText(/abcd2345/i), 'WRONG123')
    await user.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => {
      expect(screen.getByText(/invalid or expired key/i)).toBeInTheDocument()
    })
  })

  it('upper-cases and trims key entry to 8 chars', async () => {
    vi.spyOn(authApi, 'requestKey').mockResolvedValue({ delivered: true })
    const user = userEvent.setup()
    render(wrap())
    await user.type(screen.getByPlaceholderText(/crow\.ops/i), 'alice')
    await user.click(screen.getByRole('button', { name: /request key/i }))
    await waitFor(() => screen.getByPlaceholderText(/abcd2345/i))
    const input = screen.getByPlaceholderText(/abcd2345/i) as HTMLInputElement
    await user.type(input, 'abcd2345extraneous')
    expect(input.value).toBe('ABCD2345')
  })

  it('Change link returns to the username step and clears key', async () => {
    vi.spyOn(authApi, 'requestKey').mockResolvedValue({ delivered: true })
    const user = userEvent.setup()
    render(wrap())
    await user.type(screen.getByPlaceholderText(/crow\.ops/i), 'alice')
    await user.click(screen.getByRole('button', { name: /request key/i }))
    await waitFor(() => screen.getByPlaceholderText(/abcd2345/i))
    await user.click(screen.getByRole('button', { name: /change/i }))
    expect(screen.queryByPlaceholderText(/abcd2345/i)).not.toBeInTheDocument()
    expect(screen.getByPlaceholderText(/crow\.ops/i)).toBeInTheDocument()
  })

  it('shows error when request-key returns delivered=false', async () => {
    vi.spyOn(authApi, 'requestKey').mockResolvedValue({ delivered: false, error: 'discord delivery failed' })
    const user = userEvent.setup()
    render(wrap())
    await user.type(screen.getByPlaceholderText(/crow\.ops/i), 'alice')
    await user.click(screen.getByRole('button', { name: /request key/i }))
    await waitFor(() => {
      expect(screen.getByText(/discord delivery failed/i)).toBeInTheDocument()
    })
    // still on the username step
    expect(screen.queryByPlaceholderText(/abcd2345/i)).not.toBeInTheDocument()
  })
})
