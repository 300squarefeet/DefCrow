import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        crow: {
          bg:      '#0a0a0f',
          surface: '#12121a',
          border:  '#1e1e2e',
          accent:  '#7c3aed',
          danger:  '#dc2626',
          success: '#16a34a',
          text:    '#e2e8f0',
          muted:   '#64748b',
        },
      },
    },
  },
  plugins: [],
} satisfies Config
