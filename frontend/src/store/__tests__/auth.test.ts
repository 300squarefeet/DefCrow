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
    expect(result.current.isAdmin).toBe(false)
    expect(result.current.user).toBeNull()
  })

  it('sets authenticated after successful key login + carries username & role', async () => {
    vi.spyOn(authApi, 'loginWithKey').mockResolvedValue({
      token: 'tok123', username: 'admin', role: 'admin',
    })
    const { result } = renderHook(() => useAuth(), { wrapper })
    await act(async () => { await result.current.login('admin', 'ABCD2345') })
    expect(result.current.isAuthenticated).toBe(true)
    expect(result.current.user).toEqual({ username: 'admin', role: 'admin' })
    expect(result.current.isAdmin).toBe(true)
    expect(localStorage.getItem('defcrow_token')).toBe('tok123')
    expect(JSON.parse(localStorage.getItem('defcrow_user') || '{}')).toEqual({
      username: 'admin', role: 'admin',
    })
  })

  it('operator role does not flip isAdmin', async () => {
    vi.spyOn(authApi, 'loginWithKey').mockResolvedValue({
      token: 'tok456', username: 'alice', role: 'operator',
    })
    const { result } = renderHook(() => useAuth(), { wrapper })
    await act(async () => { await result.current.login('alice', 'WXYZ7890') })
    expect(result.current.isAdmin).toBe(false)
    expect(result.current.user?.role).toBe('operator')
  })

  it('requestKey forwards to the API client', async () => {
    const spy = vi.spyOn(authApi, 'requestKey').mockResolvedValue({ delivered: true })
    const { result } = renderHook(() => useAuth(), { wrapper })
    const res = await result.current.requestKey('alice')
    expect(spy).toHaveBeenCalledWith('alice')
    expect(res.delivered).toBe(true)
  })

  it('clears auth after logout', async () => {
    localStorage.setItem('defcrow_token', 'tok123')
    localStorage.setItem('defcrow_user',  JSON.stringify({ username: 'admin', role: 'admin' }))
    vi.spyOn(authApi, 'logout').mockResolvedValue(undefined)
    const { result } = renderHook(() => useAuth(), { wrapper })
    await act(async () => { await result.current.logout() })
    expect(result.current.isAuthenticated).toBe(false)
    expect(result.current.user).toBeNull()
    expect(localStorage.getItem('defcrow_user')).toBeNull()
  })
})
