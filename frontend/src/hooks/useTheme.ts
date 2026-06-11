import { useState, useEffect } from 'react'

export type Theme = 'hacker' | 'clean'

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(
    () => {
      try {
        const stored = localStorage.getItem('defcrow_theme')
        return (stored === 'hacker' || stored === 'clean' ? stored : 'hacker') as Theme
      } catch {
        return 'hacker'
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
