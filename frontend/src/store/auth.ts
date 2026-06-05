import React, { createContext, useContext, useState, useCallback } from 'react'
import { login as apiLogin, logout as apiLogout } from '../api/auth'

interface AuthContextValue {
  isAuthenticated: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(
    () => !!localStorage.getItem('defcrow_token')
  )
  const login = useCallback(async (username: string, password: string) => {
    const { token } = await apiLogin(username, password)
    localStorage.setItem('defcrow_token', token)
    setIsAuthenticated(true)
  }, [])
  const logout = useCallback(async () => {
    await apiLogout()
    setIsAuthenticated(false)
  }, [])
  return React.createElement(AuthContext.Provider, { value: { isAuthenticated, login, logout } }, children)
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
