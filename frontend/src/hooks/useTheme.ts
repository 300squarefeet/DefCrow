import { useState, useEffect } from 'react'

export type Theme = 'hacker' | 'clean'

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(
    () => {
      try {
        const stored = localStorage.getItem('defcrow_theme')
        return (stored === 'hacker' || stored === 'clean' ? stored : 'clean') as Theme
      } catch {
        return 'clean'
      }
    }
  )

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('defcrow_theme', theme)
  }, [theme])

  function setTheme(t: Theme) {
    setThemeState(t)
  }

  return { theme, setTheme }
}
