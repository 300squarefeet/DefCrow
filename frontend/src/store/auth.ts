import React, { createContext, useContext, useState, useCallback, useMemo } from 'react'
import {
  loginWithKey as apiLoginWithKey,
  requestKey   as apiRequestKey,
  logout       as apiLogout,
} from '../api/auth'
import type { RequestKeyResponse } from '../api/auth_keys'

export interface UserInfo {
  username: string
  role:     string
}

interface AuthContextValue {
  isAuthenticated: boolean
  user:            UserInfo | null
  isAdmin:         boolean
  requestKey:      (username: string) => Promise<RequestKeyResponse>
  login:           (username: string, key: string) => Promise<void>
  logout:          () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

function loadUser(): UserInfo | null {
  try {
    const raw = localStorage.getItem('defcrow_user')
    if (!raw) return null
    const parsed = JSON.parse(raw)
    // Strict shape: a tampered or stale (pre-role) localStorage entry
    // forces a re-login so a hand-edited role can't paint admin-only UI
    // sections. The server still enforces auth, but suppressing the
    // chrome avoids user confusion from clicking actions that 403.
    if (typeof parsed?.username !== 'string') return null
    if (typeof parsed?.role !== 'string')     return null
    if (parsed.role !== 'admin' && parsed.role !== 'operator') return null
    return { username: parsed.username, role: parsed.role }
  } catch { return null }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // If we have a token but the user blob is missing or malformed
  // (e.g. an older client that didn't persist a role, or a tampered
  // entry), drop the token too so we re-prompt rather than render an
  // admin shell with operator data.
  const [user, setUser] = useState<UserInfo | null>(() => {
    const u = loadUser()
    if (!u && localStorage.getItem('defcrow_token')) {
      localStorage.removeItem('defcrow_token')
      localStorage.removeItem('defcrow_user')
    }
    return u
  })
  const [isAuthenticated, setIsAuthenticated] = useState(
    () => !!localStorage.getItem('defcrow_token')
  )

  const requestKey = useCallback(async (username: string) => {
    return apiRequestKey(username)
  }, [])

  const login = useCallback(async (username: string, key: string) => {
    const res = await apiLoginWithKey(username, key)
    localStorage.setItem('defcrow_token', res.token)
    const u: UserInfo = { username: res.username, role: res.role }
    localStorage.setItem('defcrow_user', JSON.stringify(u))
    setUser(u)
    setIsAuthenticated(true)
  }, [])

  const logout = useCallback(async () => {
    await apiLogout().catch(() => {})
    localStorage.removeItem('defcrow_token')
    localStorage.removeItem('defcrow_user')
    setUser(null)
    setIsAuthenticated(false)
  }, [])

  const isAdmin = useMemo(() => user?.role === 'admin', [user])

  return React.createElement(
    AuthContext.Provider,
    { value: { isAuthenticated, user, isAdmin, requestKey, login, logout } },
    children,
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
