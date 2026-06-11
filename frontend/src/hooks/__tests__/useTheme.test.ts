import { describe, it, expect, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useTheme } from '../useTheme'

describe('useTheme', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
  })

  it('defaults to hacker theme', () => {
    const { result } = renderHook(() => useTheme())
    expect(result.current.theme).toBe('hacker')
  })

  it('sets data-theme attribute on html element', () => {
    const { result } = renderHook(() => useTheme())
    act(() => result.current.setTheme('clean'))
    expect(document.documentElement.getAttribute('data-theme')).toBe('clean')
    expect(result.current.theme).toBe('clean')
  })

  it('persists theme in localStorage', () => {
    const { result } = renderHook(() => useTheme())
    act(() => result.current.setTheme('clean'))
    expect(localStorage.getItem('defcrow_theme')).toBe('clean')
  })
})
