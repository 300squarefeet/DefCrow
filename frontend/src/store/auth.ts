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
    if (typeof parsed?.username !== 'string') return null
    // Tolerate older payloads that didn't store a role: treat as operator until next login.
    const role = typeof parsed?.role === 'string' ? parsed.role : 'operator'
    return { username: parsed.username, role }
  } catch { return null }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(
    () => !!localStorage.getItem('defcrow_token')
  )
  const [user, setUser] = useState<UserInfo | null>(() => loadUser())

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
