import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import React from 'react'
import { MemoryRouter } from 'react-router-dom'
import SettingsPage from '../SettingsPage'
import { AuthProvider } from '../../store/auth'
import * as adminApi from '../../api/admin'

function renderWith({ admin }: { admin: boolean }) {
  localStorage.setItem('defcrow_token', 'tok')
  localStorage.setItem('defcrow_user', JSON.stringify({
    username: admin ? 'admin' : 'alice',
    role:     admin ? 'admin' : 'operator',
  }))
  return render(
    <MemoryRouter initialEntries={['/settings']}>
      <AuthProvider>
        <SettingsPage />
      </AuthProvider>
    </MemoryRouter>
  )
}

describe('SettingsPage admin sections', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  it('hides Operators + Authentication sections when not admin', () => {
    renderWith({ admin: false })
    expect(screen.queryByText('Operators')).not.toBeInTheDocument()
    expect(screen.queryByText('Authentication')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /add operator/i })).not.toBeInTheDocument()
    expect(screen.queryByText(/Auth Discord webhook URL/i)).not.toBeInTheDocument()
  })

  it('shows Operators + Authentication when admin and loads users + settings', async () => {
    const listSpy = vi.spyOn(adminApi, 'adminListUsers').mockResolvedValue([
      { username: 'admin',  role: 'admin',    created_at: '2026-06-10T10:00:00Z' },
      { username: 'alice',  role: 'operator', created_at: '2026-06-11T11:00:00Z' },
    ])
    const settingsSpy = vi.spyOn(adminApi, 'adminGetAuthSettings').mockResolvedValue({
      discord_webhook: 'https://discord.com/api/webhooks/123/abc',
    })

    renderWith({ admin: true })

    expect(screen.getByText('Operators')).toBeInTheDocument()
    expect(screen.getByText('Authentication')).toBeInTheDocument()
    await waitFor(() => expect(listSpy).toHaveBeenCalled())
    await waitFor(() => expect(settingsSpy).toHaveBeenCalled())

    expect(await screen.findByText(/admin \(you\)/i)).toBeInTheDocument()
    expect(screen.getByText(/alice/)).toBeInTheDocument()
    expect((screen.getByDisplayValue('https://discord.com/api/webhooks/123/abc') as HTMLInputElement).value)
      .toBe('https://discord.com/api/webhooks/123/abc')
  })

  it('admin can add a new operator', async () => {
    vi.spyOn(adminApi, 'adminListUsers')
      .mockResolvedValueOnce([
        { username: 'admin', role: 'admin', created_at: '2026-06-10T10:00:00Z' },
      ])
      .mockResolvedValueOnce([
        { username: 'admin', role: 'admin',    created_at: '2026-06-10T10:00:00Z' },
        { username: 'bob',   role: 'operator', created_at: '2026-06-13T15:00:00Z' },
      ])
    vi.spyOn(adminApi, 'adminGetAuthSettings').mockResolvedValue({ discord_webhook: null })
    const addSpy = vi.spyOn(adminApi, 'adminAddUser').mockResolvedValue({
      username: 'bob', role: 'operator', created_at: '2026-06-13T15:00:00Z',
    })

    const user = userEvent.setup()
    renderWith({ admin: true })

    await screen.findByText(/admin \(you\)/i)
    await user.type(screen.getByPlaceholderText(/e\.g\. alice/i), 'bob')
    await user.click(screen.getByRole('button', { name: /add operator/i }))

    await waitFor(() => expect(addSpy).toHaveBeenCalledWith('bob', 'operator'))
    await waitFor(() => expect(screen.getByText(/bob/)).toBeInTheDocument())
  })

  it('admin cannot delete themselves (button disabled)', async () => {
    vi.spyOn(adminApi, 'adminListUsers').mockResolvedValue([
      { username: 'admin', role: 'admin', created_at: '2026-06-10T10:00:00Z' },
    ])
    vi.spyOn(adminApi, 'adminGetAuthSettings').mockResolvedValue({ discord_webhook: null })

    renderWith({ admin: true })
    await screen.findByText(/admin \(you\)/i)
    const deleteButtons = screen.getAllByRole('button', { name: /delete/i })
    expect(deleteButtons[0]).toBeDisabled()
  })

  it('admin can save webhook then test it', async () => {
    vi.spyOn(adminApi, 'adminListUsers').mockResolvedValue([])
    vi.spyOn(adminApi, 'adminGetAuthSettings').mockResolvedValue({ discord_webhook: '' })
    const setSpy = vi.spyOn(adminApi, 'adminSetAuthSettings').mockResolvedValue({
      discord_webhook: 'https://discord.com/api/webhooks/9/x',
    })
    const testSpy = vi.spyOn(adminApi, 'adminTestAuthWebhook').mockResolvedValue({ ok: true })

    const user = userEvent.setup()
    renderWith({ admin: true })

    const input = await screen.findByTestId('auth-webhook-input')
    await user.type(input, 'https://discord.com/api/webhooks/9/x')
    await user.click(screen.getByRole('button', { name: /save webhook/i }))
    await waitFor(() => expect(setSpy).toHaveBeenCalledWith({
      discord_webhook: 'https://discord.com/api/webhooks/9/x',
    }))

    await user.click(screen.getByTestId('auth-webhook-test'))
    await waitFor(() => expect(testSpy).toHaveBeenCalled())
    expect(await screen.findByText(/webhook reachable/i)).toBeInTheDocument()
  })
})
