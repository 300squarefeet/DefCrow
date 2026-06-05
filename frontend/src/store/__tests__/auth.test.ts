import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import React from 'react'
import { AuthProvider, useAuth } from '../auth'
import * as authApi from '../../api/auth'

const wrapper = ({ children }: { children: React.ReactNode }) =>
  React.createElement(AuthProvider, null, children)

describe('useAuth', () => {
  beforeEach(() => { localStorage.clear(); vi.restoreAllMocks() })

  it('starts unauthenticated when no token in storage', () => {
    const { result } = renderHook(() => useAuth(), { wrapper })
    expect(result.current.isAuthenticated).toBe(false)
  })

  it('sets authenticated after successful login', async () => {
    vi.spyOn(authApi, 'login').mockResolvedValue({ token: 'tok123', expires_in: 86400 })
    const { result } = renderHook(() => useAuth(), { wrapper })
    await act(async () => { await result.current.login('admin', 'password') })
    expect(result.current.isAuthenticated).toBe(true)
    expect(localStorage.getItem('defcrow_token')).toBe('tok123')
  })

  it('clears auth after logout', async () => {
    localStorage.setItem('defcrow_token', 'tok123')
    vi.spyOn(authApi, 'logout').mockResolvedValue(undefined)
    const { result } = renderHook(() => useAuth(), { wrapper })
    await act(async () => { await result.current.logout() })
    expect(result.current.isAuthenticated).toBe(false)
  })
})
