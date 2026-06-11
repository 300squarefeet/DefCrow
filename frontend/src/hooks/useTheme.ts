import { useState, useEffect } from 'react'

export type Theme = 'hacker' | 'clean'

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(
    () => (localStorage.getItem('defcrow_theme') as Theme) ?? 'hacker'
  )

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  function setTheme(t: Theme) {
    localStorage.setItem('defcrow_theme', t)
    setThemeState(t)
  }

  return { theme, setTheme }
}
