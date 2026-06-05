# DefCrow Frontend — Implementation Plan (3 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the React+Vite frontend: login page, loader generator form with all 15 OPSEC toggles, AppDomain config panel, real-time WebSocket progress display, and binary download — all served as static files from the Axum backend.

**Architecture:** Single-page application (React Router). Auth token stored in `localStorage`. Axios interceptor auto-injects `Authorization: Bearer` header and redirects to `/login` on 401. WebSocket subscription starts immediately after POST /api/generate returns `job_id`. Three main pages: LoginPage, GeneratorPage, JobStatusPage.

**Tech Stack:** React 18, TypeScript, Vite, React Router v6, Axios, Tailwind CSS v3, Shadcn/ui (Radix primitives), native browser WebSocket API.

**Prerequisite:** Plan 2 complete — Axum server runs on `http://localhost:8080`.

---

## File Map

| File | Responsibility |
|---|---|
| `frontend/package.json` | Vite + React + Tailwind deps |
| `frontend/vite.config.ts` | Proxy API to :8080 in dev, static build for prod |
| `frontend/src/main.tsx` | React root + React Router |
| `frontend/src/api/client.ts` | Axios instance + interceptors |
| `frontend/src/api/auth.ts` | login(), logout() API calls |
| `frontend/src/api/generate.ts` | generate() API call, types |
| `frontend/src/hooks/useJobSocket.ts` | WebSocket hook, returns JobStatus |
| `frontend/src/store/auth.ts` | Auth context + token state |
| `frontend/src/pages/LoginPage.tsx` | Login form |
| `frontend/src/pages/GeneratorPage.tsx` | Main generator form |
| `frontend/src/pages/JobStatusPage.tsx` | Progress bar + download button |
| `frontend/src/components/OpsecFeatures.tsx` | 15 OPSEC toggles |
| `frontend/src/components/AppDomainConfig.tsx` | CLR version, target process, DM type |
| `frontend/src/components/PeMetadata.tsx` | Company, version, signing config |
| `frontend/src/components/ProtectedRoute.tsx` | Redirect to /login if not auth'd |

---

### Task 1: Project Setup + Vite Config

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/tsconfig.json`
- Create: `frontend/tailwind.config.ts`
- Create: `frontend/postcss.config.cjs`
- Create: `frontend/index.html`
- Create: `frontend/src/main.tsx`

- [ ] **Step 1: Create `frontend/package.json`**

```json
{
  "name": "defcrow-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev":   "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react":              "^18.2.0",
    "react-dom":          "^18.2.0",
    "react-router-dom":   "^6.23.0",
    "axios":              "^1.7.0",
    "@radix-ui/react-switch":   "^1.1.0",
    "@radix-ui/react-progress": "^1.1.0",
    "@radix-ui/react-label":    "^2.1.0",
    "@radix-ui/react-select":   "^2.1.0",
    "@radix-ui/react-dialog":   "^1.1.0",
    "clsx":     "^2.1.0",
    "lucide-react": "^0.378.0"
  },
  "devDependencies": {
    "@types/react":         "^18.2.0",
    "@types/react-dom":     "^18.2.0",
    "@vitejs/plugin-react": "^4.2.0",
    "autoprefixer":         "^10.4.0",
    "postcss":              "^8.4.0",
    "tailwindcss":          "^3.4.0",
    "typescript":           "^5.4.0",
    "vite":                 "^5.2.0",
    "vitest":               "^1.6.0",
    "@vitest/ui":           "^1.6.0",
    "@testing-library/react":       "^15.0.0",
    "@testing-library/user-event":  "^14.5.0"
  }
}
```

- [ ] **Step 2: Create `frontend/vite.config.ts`**

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api':  'http://localhost:8080',
      '/ws':   { target: 'ws://localhost:8080', ws: true },
    },
  },
  build: {
    outDir: 'dist',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test-setup.ts',
  },
})
```

- [ ] **Step 3: Create `frontend/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"],
  "exclude": ["node_modules"]
}
```

- [ ] **Step 4: Create `frontend/tailwind.config.ts`**

```typescript
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
```

- [ ] **Step 5: Create `frontend/postcss.config.cjs`**

```javascript
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
```

- [ ] **Step 6: Create `frontend/index.html`**

```html
<!doctype html>
<html lang="en" class="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>DefCrow</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  </head>
  <body class="bg-crow-bg text-crow-text antialiased">
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 7: Create `frontend/src/main.tsx`**

```tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)
```

- [ ] **Step 8: Create `frontend/src/index.css`**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root { color-scheme: dark; }
  body { @apply bg-crow-bg text-crow-text; }
  * { @apply border-crow-border; }
}
```

- [ ] **Step 9: Install dependencies**

```bash
cd frontend && npm install
```

Expected: `added XXX packages`

- [ ] **Step 10: Verify build**

```bash
cd frontend && npm run build
```

Expected: `dist/index.html` created

- [ ] **Step 11: Commit**

```bash
git add frontend/
git commit -m "feat(frontend): Vite + React + Tailwind project setup"
```

---

### Task 2: API Client + Auth Context

**Files:**
- Create: `frontend/src/api/client.ts`
- Create: `frontend/src/api/auth.ts`
- Create: `frontend/src/api/generate.ts`
- Create: `frontend/src/store/auth.ts`

- [ ] **Step 1: Create `frontend/src/api/client.ts`**

```typescript
import axios from 'axios'

export const client = axios.create({
  baseURL: '/api',
  timeout: 30_000,
})

// Inject token on every request
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('defcrow_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Redirect to /login on 401
client.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('defcrow_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  },
)
```

- [ ] **Step 2: Create `frontend/src/api/auth.ts`**

```typescript
import { client } from './client'

export interface LoginResponse {
  token:      string
  expires_in: number
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const { data } = await client.post<LoginResponse>('/auth/login', { username, password })
  return data
}

export async function logout(): Promise<void> {
  await client.post('/auth/logout').catch(() => {})
  localStorage.removeItem('defcrow_token')
}
```

- [ ] **Step 3: Create `frontend/src/api/generate.ts`**

```typescript
import { client } from './client'

export type LoaderType = 'Binary' | 'Dll' | 'AppDomain' | 'Injector'
export type Encryption  = 'Aes256' | 'Chacha20'

export const ALL_FEATURES = [
  'DirectSyscall', 'UnhookDisk', 'UnhookKnownDlls',
  'ModuleStomp',   'SleepEncrypt', 'StackSpoof',
  'SandboxDomain', 'SandboxUser',  'PpidSpoof',
  'AmsiHwbp',      'EtwHwbp',      'PeSpoofing',
  'Staged',        'AppDomain',     'ThreadlessInject',
] as const
export type Feature = typeof ALL_FEATURES[number]

export interface PeMetadataReq {
  company_name:      string
  file_description:  string
  product_name:      string
  file_version:      string
  original_filename: string
  legal_copyright:   string
  sign:              boolean
  cert_pem?:         string
}

export interface AppDomainReq {
  clr_version:      string   // e.g., "v4.0.30319"
  net_version:      string   // e.g., "4.0"
  appdomain_type:   string   // e.g., "EvilDomain.Manager"
  target_assembly:  string   // path or URL
}

export interface GenerateRequest {
  loader_type:        LoaderType
  features:           Feature[]
  encryption:         Encryption
  shellcode_hex:      string
  key_hex:            string
  iv_hex:             string
  pe_config?:         PeMetadataReq
  appdomain_config?:  AppDomainReq
}

export interface GenerateResponse {
  job_id: string
}

export async function generate(req: GenerateRequest): Promise<GenerateResponse> {
  const { data } = await client.post<GenerateResponse>('/generate', req)
  return data
}
```

- [ ] **Step 4: Create `frontend/src/store/auth.ts`**

```typescript
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

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
```

- [ ] **Step 5: Write unit test for auth store**

```typescript
// frontend/src/store/__tests__/auth.test.ts
import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { AuthProvider, useAuth } from '../auth'
import * as authApi from '../../api/auth'

const wrapper = ({ children }: { children: React.ReactNode }) =>
  React.createElement(AuthProvider, null, children)

describe('useAuth', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  it('starts unauthenticated when no token in storage', () => {
    const { result } = renderHook(() => useAuth(), { wrapper })
    expect(result.current.isAuthenticated).toBe(false)
  })

  it('sets authenticated after successful login', async () => {
    vi.spyOn(authApi, 'login').mockResolvedValue({ token: 'tok123', expires_in: 86400 })
    const { result } = renderHook(() => useAuth(), { wrapper })

    await act(async () => {
      await result.current.login('admin', 'password')
    })

    expect(result.current.isAuthenticated).toBe(true)
    expect(localStorage.getItem('defcrow_token')).toBe('tok123')
  })

  it('clears auth after logout', async () => {
    localStorage.setItem('defcrow_token', 'tok123')
    vi.spyOn(authApi, 'logout').mockResolvedValue()
    const { result } = renderHook(() => useAuth(), { wrapper })

    await act(async () => {
      await result.current.logout()
    })

    expect(result.current.isAuthenticated).toBe(false)
  })
})
```

- [ ] **Step 6: Create test setup file**

```typescript
// frontend/src/test-setup.ts
import '@testing-library/jest-dom'
```

- [ ] **Step 7: Run auth tests**

```bash
cd frontend && npm run test -- --run src/store/__tests__/auth.test.ts
```

Expected: 3 tests pass

- [ ] **Step 8: Commit**

```bash
git add frontend/src/
git commit -m "feat(frontend): Axios client + auth context + login/logout API"
```

---

### Task 3: WebSocket Hook

**Files:**
- Create: `frontend/src/hooks/useJobSocket.ts`

- [ ] **Step 1: Write failing test**

```typescript
// frontend/src/hooks/__tests__/useJobSocket.test.ts
import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useJobSocket } from '../useJobSocket'

// Mock WebSocket
class MockWS {
  onmessage: ((e: MessageEvent) => void) | null = null
  onclose: (() => void) | null = null
  onerror: ((e: Event) => void) | null = null
  close = vi.fn()

  emit(data: object) {
    this.onmessage?.({ data: JSON.stringify(data) } as MessageEvent)
  }
}

let mockWs: MockWS
vi.stubGlobal('WebSocket', vi.fn(() => {
  mockWs = new MockWS()
  return mockWs
}))

describe('useJobSocket', () => {
  it('starts with null status', () => {
    const { result } = renderHook(() => useJobSocket('job-123'))
    expect(result.current.status).toBeNull()
  })

  it('updates status on message', async () => {
    const { result } = renderHook(() => useJobSocket('job-123'))
    act(() => {
      mockWs.emit({ status: 'building', progress: 40, msg: 'Compiling...' })
    })
    expect(result.current.status).toMatchObject({ status: 'building', progress: 40 })
  })

  it('closes socket on unmount', () => {
    const { unmount } = renderHook(() => useJobSocket('job-123'))
    unmount()
    expect(mockWs.close).toHaveBeenCalled()
  })

  it('does not connect if jobId is null', () => {
    const createWS = vi.fn()
    vi.stubGlobal('WebSocket', createWS)
    renderHook(() => useJobSocket(null))
    expect(createWS).not.toHaveBeenCalled()
  })
})
```

- [ ] **Step 2: Run test — verify failure**

```bash
cd frontend && npm run test -- --run src/hooks/__tests__/useJobSocket.test.ts
```

Expected: FAIL

- [ ] **Step 3: Implement useJobSocket**

```typescript
// frontend/src/hooks/useJobSocket.ts
import { useEffect, useRef, useState } from 'react'

export interface JobStatus {
  status:      'queued' | 'building' | 'done' | 'error'
  progress?:   number
  msg?:        string
  download_id?: string
}

export function useJobSocket(jobId: string | null) {
  const [status, setStatus] = useState<JobStatus | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!jobId) return

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${window.location.host}/ws/jobs/${jobId}`)
    wsRef.current = ws

    ws.onmessage = (e) => {
      try {
        setStatus(JSON.parse(e.data) as JobStatus)
      } catch {}
    }
    ws.onerror = () => {
      setStatus({ status: 'error', msg: 'WebSocket connection failed' })
    }

    return () => {
      ws.close()
      wsRef.current = null
    }
  }, [jobId])

  return { status }
}
```

- [ ] **Step 4: Run tests — verify pass**

```bash
cd frontend && npm run test -- --run src/hooks/__tests__/useJobSocket.test.ts
```

Expected: 4 tests pass

- [ ] **Step 5: Commit**

```bash
git add frontend/src/hooks/
git commit -m "feat(frontend): useJobSocket WebSocket hook with real-time status"
```

---

### Task 4: LoginPage

**Files:**
- Create: `frontend/src/pages/LoginPage.tsx`
- Create: `frontend/src/components/ProtectedRoute.tsx`
- Modify: `frontend/src/App.tsx`

- [ ] **Step 1: Write failing test**

```typescript
// frontend/src/pages/__tests__/LoginPage.test.tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import LoginPage from '../LoginPage'
import { AuthProvider } from '../../store/auth'
import * as authApi from '../../api/auth'

const Wrapper = ({ children }: { children: React.ReactNode }) => (
  <MemoryRouter><AuthProvider>{children}</AuthProvider></MemoryRouter>
)

describe('LoginPage', () => {
  it('renders username and password fields', () => {
    render(<LoginPage />, { wrapper: Wrapper })
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
  })

  it('shows error on invalid credentials', async () => {
    vi.spyOn(authApi, 'login').mockRejectedValue({ response: { status: 401 } })
    render(<LoginPage />, { wrapper: Wrapper })

    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'wrong' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument()
    })
  })

  it('disables submit button while loading', async () => {
    vi.spyOn(authApi, 'login').mockImplementation(() => new Promise(() => {}))
    render(<LoginPage />, { wrapper: Wrapper })

    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'password' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /signing in/i })).toBeDisabled()
    })
  })
})
```

- [ ] **Step 2: Implement LoginPage**

```tsx
// frontend/src/pages/LoginPage.tsx
import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../store/auth'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState<string | null>(null)
  const [loading,  setLoading]  = useState(false)
  const { login }               = useAuth()
  const navigate                = useNavigate()

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await login(username, password)
      navigate('/')
    } catch (err: any) {
      setError(
        err?.response?.status === 401
          ? 'Invalid credentials'
          : 'Connection error — is the server running?'
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-crow-bg">
      <div className="w-full max-w-sm rounded-2xl bg-crow-surface border border-crow-border p-8 shadow-2xl">
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-bold text-crow-text tracking-tight">DefCrow</h1>
          <p className="text-crow-muted text-sm mt-1">Loader Generation Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label htmlFor="username" className="block text-sm text-crow-muted mb-1">
              Username
            </label>
            <input
              id="username"
              type="text"
              required
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-lg bg-crow-bg border border-crow-border px-3 py-2
                         text-crow-text text-sm focus:outline-none focus:border-crow-accent
                         focus:ring-1 focus:ring-crow-accent transition"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm text-crow-muted mb-1">
              Password
            </label>
            <input
              id="password"
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg bg-crow-bg border border-crow-border px-3 py-2
                         text-crow-text text-sm focus:outline-none focus:border-crow-accent
                         focus:ring-1 focus:ring-crow-accent transition"
            />
          </div>

          {error && (
            <p className="text-crow-danger text-sm rounded-lg bg-red-950/40 px-3 py-2 border border-red-800">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 rounded-lg bg-crow-accent hover:bg-violet-700
                       text-white font-medium text-sm transition disabled:opacity-50
                       disabled:cursor-not-allowed"
          >
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}
```

- [ ] **Step 3: Create ProtectedRoute**

```tsx
// frontend/src/components/ProtectedRoute.tsx
import { Navigate } from 'react-router-dom'
import { useAuth } from '../store/auth'

export default function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />
}
```

- [ ] **Step 4: Create App.tsx**

```tsx
// frontend/src/App.tsx
import { Routes, Route } from 'react-router-dom'
import { AuthProvider } from './store/auth'
import ProtectedRoute from './components/ProtectedRoute'
import LoginPage     from './pages/LoginPage'
import GeneratorPage from './pages/GeneratorPage'
import JobStatusPage from './pages/JobStatusPage'

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={
          <ProtectedRoute><GeneratorPage /></ProtectedRoute>
        } />
        <Route path="/job/:id" element={
          <ProtectedRoute><JobStatusPage /></ProtectedRoute>
        } />
      </Routes>
    </AuthProvider>
  )
}
```

- [ ] **Step 5: Run login tests**

```bash
cd frontend && npm run test -- --run src/pages/__tests__/LoginPage.test.tsx
```

Expected: 3 tests pass

- [ ] **Step 6: Commit**

```bash
git add frontend/src/
git commit -m "feat(frontend): LoginPage + ProtectedRoute + App router"
```

---

### Task 5: OpsecFeatures Component

**Files:**
- Create: `frontend/src/components/OpsecFeatures.tsx`

- [ ] **Step 1: Write failing test**

```typescript
// frontend/src/components/__tests__/OpsecFeatures.test.tsx
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import OpsecFeatures from '../OpsecFeatures'
import { ALL_FEATURES } from '../../api/generate'

describe('OpsecFeatures', () => {
  it('renders all 15 feature toggles', () => {
    render(<OpsecFeatures selected={[]} onChange={vi.fn()} />)
    expect(screen.getAllByRole('switch')).toHaveLength(15)
  })

  it('shows selected features as checked', () => {
    render(<OpsecFeatures selected={['AmsiHwbp', 'EtwHwbp']} onChange={vi.fn()} />)
    const amsi = screen.getByTestId('toggle-AmsiHwbp')
    expect(amsi).toHaveAttribute('data-state', 'checked')
  })

  it('calls onChange with new set when toggled', () => {
    const onChange = vi.fn()
    render(<OpsecFeatures selected={[]} onChange={onChange} />)
    fireEvent.click(screen.getByTestId('toggle-AmsiHwbp'))
    expect(onChange).toHaveBeenCalledWith(expect.arrayContaining(['AmsiHwbp']))
  })
})
```

- [ ] **Step 2: Implement OpsecFeatures**

```tsx
// frontend/src/components/OpsecFeatures.tsx
import { Feature, ALL_FEATURES } from '../api/generate'

const FEATURE_META: Record<Feature, { label: string; desc: string; category: string }> = {
  DirectSyscall:   { label: 'Indirect Syscalls',    desc: 'SSN resolved at runtime, trampoline via ntdll stub — call stack appears from ntdll', category: 'Evasion' },
  UnhookDisk:      { label: 'NTDLL Unhook (Disk)',   desc: 'Reload clean ntdll from disk, overwrite hooked .text section', category: 'Evasion' },
  UnhookKnownDlls: { label: 'NTDLL Unhook (KnownDLLs)', desc: 'Map ntdll from KnownDLLs, resistant to kernel patch hooks', category: 'Evasion' },
  ModuleStomp:     { label: 'Module Stomping',       desc: 'Shellcode written into legit DLL .text — MEM_IMAGE, not MEM_PRIVATE', category: 'Evasion' },
  SleepEncrypt:    { label: 'Sleep Masking (Ekko)',   desc: 'Full PE XOR-encrypted during sleep via TimerQueueTimer callbacks', category: 'Evasion' },
  StackSpoof:      { label: 'Stack Spoofing',        desc: 'Synthetic return addresses from ntdll/kernel32 before shellcode call', category: 'Evasion' },
  SandboxDomain:   { label: 'Domain Check',          desc: 'Exit if not domain-joined via NetGetJoinInformation', category: 'Sandbox' },
  SandboxUser:     { label: 'User / Uptime Check',   desc: 'Exit if mouse static, RAM < 4GB, uptime < 5 min', category: 'Sandbox' },
  PpidSpoof:       { label: 'PPID Spoofing',         desc: 'Parent process spoofed via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS', category: 'Injection' },
  AmsiHwbp:        { label: 'AMSI Bypass (HW BP)',   desc: 'DR0=AmsiScanBuffer, VEH sets Rax=0 — zero memory IOC', category: 'Bypass' },
  EtwHwbp:         { label: 'ETW Bypass (HW BP)',    desc: 'DR1=EtwEventWrite, VEH suppresses event — zero memory IOC', category: 'Bypass' },
  PeSpoofing:      { label: 'PE Metadata Spoof',     desc: 'Version info / certificate cloned from legitimate binary', category: 'Misc' },
  Staged:          { label: 'Staged Payload',        desc: 'Shellcode fetched from remote URL at runtime (not embedded)', category: 'Delivery' },
  AppDomain:       { label: 'AppDomain Injection',   desc: 'ICLRRuntimeHost2 + .config AppDomainManager hijacking', category: 'Injection' },
  ThreadlessInject: { label: 'Threadless Injection', desc: 'TpAllocWork callback trampoline — no CreateRemoteThread', category: 'Injection' },
}

const CATEGORIES = ['Evasion', 'Bypass', 'Injection', 'Sandbox', 'Delivery', 'Misc']

interface Props {
  selected: Feature[]
  onChange: (features: Feature[]) => void
}

export default function OpsecFeatures({ selected, onChange }: Props) {
  function toggle(f: Feature) {
    onChange(
      selected.includes(f)
        ? selected.filter((x) => x !== f)
        : [...selected, f]
    )
  }

  return (
    <div className="space-y-5">
      {CATEGORIES.map((cat) => {
        const features = ALL_FEATURES.filter((f) => FEATURE_META[f].category === cat)
        if (!features.length) return null
        return (
          <div key={cat}>
            <p className="text-xs uppercase tracking-widest text-crow-muted mb-2">{cat}</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {features.map((f) => {
                const { label, desc } = FEATURE_META[f]
                const enabled = selected.includes(f)
                return (
                  <button
                    key={f}
                    role="switch"
                    aria-checked={enabled}
                    data-state={enabled ? 'checked' : 'unchecked'}
                    data-testid={`toggle-${f}`}
                    onClick={() => toggle(f)}
                    className={`text-left rounded-xl border p-3 transition group
                      ${enabled
                        ? 'border-crow-accent bg-violet-950/30'
                        : 'border-crow-border bg-crow-surface hover:border-violet-700'
                      }`}
                  >
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full transition
                        ${enabled ? 'bg-crow-accent' : 'bg-crow-border'}`} />
                      <span className="text-sm font-medium text-crow-text">{label}</span>
                    </div>
                    <p className="text-xs text-crow-muted mt-1 ml-4 leading-relaxed">{desc}</p>
                  </button>
                )
              })}
            </div>
          </div>
        )
      })}
    </div>
  )
}
```

- [ ] **Step 3: Run tests**

```bash
cd frontend && npm run test -- --run src/components/__tests__/OpsecFeatures.test.tsx
```

Expected: 3 tests pass

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/OpsecFeatures.tsx
git commit -m "feat(frontend): OpsecFeatures component — 15 categorized toggles"
```

---

### Task 6: AppDomainConfig + PeMetadata Components

**Files:**
- Create: `frontend/src/components/AppDomainConfig.tsx`
- Create: `frontend/src/components/PeMetadata.tsx`

- [ ] **Step 1: Implement AppDomainConfig**

```tsx
// frontend/src/components/AppDomainConfig.tsx
import { AppDomainReq } from '../api/generate'

interface Props {
  value:    AppDomainReq
  onChange: (v: AppDomainReq) => void
}

const CLR_VERSIONS  = ['v2.0.50727', 'v4.0.30319']
const NET_VERSIONS  = ['2.0', '3.5', '4.0', '4.5', '4.8']

export default function AppDomainConfig({ value, onChange }: Props) {
  function set<K extends keyof AppDomainReq>(k: K, v: AppDomainReq[K]) {
    onChange({ ...value, [k]: v })
  }

  return (
    <div className="rounded-xl border border-crow-accent/40 bg-violet-950/10 p-4 space-y-4">
      <p className="text-sm font-semibold text-crow-accent">AppDomain Configuration</p>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-crow-muted mb-1">CLR Version</label>
          <select
            value={value.clr_version}
            onChange={(e) => set('clr_version', e.target.value)}
            className="w-full rounded-lg bg-crow-bg border border-crow-border px-2 py-1.5
                       text-sm text-crow-text focus:border-crow-accent focus:outline-none"
          >
            {CLR_VERSIONS.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs text-crow-muted mb-1">.NET Version</label>
          <select
            value={value.net_version}
            onChange={(e) => set('net_version', e.target.value)}
            className="w-full rounded-lg bg-crow-bg border border-crow-border px-2 py-1.5
                       text-sm text-crow-text focus:border-crow-accent focus:outline-none"
          >
            {NET_VERSIONS.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
      </div>

      <div>
        <label className="block text-xs text-crow-muted mb-1">
          AppDomainManager Type
          <span className="ml-1 text-crow-muted/60">(Namespace.ClassName)</span>
        </label>
        <input
          type="text"
          placeholder="EvilDomain.Manager"
          value={value.appdomain_type}
          onChange={(e) => set('appdomain_type', e.target.value)}
          className="w-full rounded-lg bg-crow-bg border border-crow-border px-3 py-1.5
                     text-sm text-crow-text focus:border-crow-accent focus:outline-none"
        />
      </div>

      <div>
        <label className="block text-xs text-crow-muted mb-1">Target Assembly Path / URL</label>
        <input
          type="text"
          placeholder="C:\path\to\evil.dll or https://..."
          value={value.target_assembly}
          onChange={(e) => set('target_assembly', e.target.value)}
          className="w-full rounded-lg bg-crow-bg border border-crow-border px-3 py-1.5
                     text-sm text-crow-text focus:border-crow-accent focus:outline-none"
        />
      </div>

      <div className="rounded-lg bg-amber-950/30 border border-amber-800/50 p-3">
        <p className="text-xs text-amber-400 font-medium mb-1">Generated Output</p>
        <p className="text-xs text-crow-muted">
          1. <code className="text-crow-text">loader.dll</code> — AppDomainManager DLL
          via ICLRRuntimeHost2
        </p>
        <p className="text-xs text-crow-muted mt-1">
          2. <code className="text-crow-text">loader.exe.config</code> — .config profile
          that injects your AppDomainManager at CLR startup
        </p>
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Implement PeMetadata**

```tsx
// frontend/src/components/PeMetadata.tsx
import { PeMetadataReq } from '../api/generate'

interface Props {
  value:    PeMetadataReq
  onChange: (v: PeMetadataReq) => void
  enabled:  boolean
  onToggle: (v: boolean) => void
}

const PRESETS: Record<string, Partial<PeMetadataReq>> = {
  'Microsoft svchost': {
    company_name:      'Microsoft Corporation',
    file_description:  'Host Process for Windows Services',
    product_name:      'Microsoft Windows Operating System',
    file_version:      '10.0.19041.1',
    original_filename: 'svchost.exe',
    legal_copyright:   '© Microsoft Corporation. All rights reserved.',
  },
  'Microsoft explorer': {
    company_name:      'Microsoft Corporation',
    file_description:  'Windows Explorer',
    product_name:      'Microsoft Windows Operating System',
    file_version:      '10.0.19041.1',
    original_filename: 'explorer.exe',
    legal_copyright:   '© Microsoft Corporation. All rights reserved.',
  },
  'Custom': {},
}

export default function PeMetadata({ value, onChange, enabled, onToggle }: Props) {
  function set<K extends keyof PeMetadataReq>(k: K, v: PeMetadataReq[K]) {
    onChange({ ...value, [k]: v })
  }

  function applyPreset(name: string) {
    onChange({ ...value, ...PRESETS[name] })
  }

  return (
    <div className="rounded-xl border border-crow-border bg-crow-surface p-4 space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold text-crow-text">PE Metadata Spoofing</p>
        <button
          role="switch"
          aria-checked={enabled}
          onClick={() => onToggle(!enabled)}
          className={`relative inline-flex h-5 w-9 rounded-full transition
            ${enabled ? 'bg-crow-accent' : 'bg-crow-border'}`}
        >
          <span className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform
            ${enabled ? 'translate-x-4' : 'translate-x-0'}`} />
        </button>
      </div>

      {enabled && (
        <>
          <div className="flex gap-2 flex-wrap">
            {Object.keys(PRESETS).map((name) => (
              <button
                key={name}
                onClick={() => applyPreset(name)}
                className="text-xs px-2 py-1 rounded bg-crow-bg border border-crow-border
                           hover:border-crow-accent text-crow-muted hover:text-crow-text transition"
              >
                {name}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              ['Company', 'company_name'],
              ['File Description', 'file_description'],
              ['Product Name', 'product_name'],
              ['File Version', 'file_version'],
              ['Original Filename', 'original_filename'],
              ['Legal Copyright', 'legal_copyright'],
            ].map(([label, key]) => (
              <div key={key}>
                <label className="block text-xs text-crow-muted mb-1">{label}</label>
                <input
                  type="text"
                  value={value[key as keyof PeMetadataReq] as string}
                  onChange={(e) => set(key as keyof PeMetadataReq, e.target.value as any)}
                  className="w-full rounded-lg bg-crow-bg border border-crow-border px-2 py-1.5
                             text-xs text-crow-text focus:border-crow-accent focus:outline-none"
                />
              </div>
            ))}
          </div>

          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={value.sign}
              onChange={(e) => set('sign', e.target.checked)}
              className="rounded accent-crow-accent"
            />
            <span className="text-xs text-crow-muted">
              Self-sign with osslsigncode
            </span>
          </label>
        </>
      )}
    </div>
  )
}
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/
git commit -m "feat(frontend): AppDomainConfig + PeMetadata components"
```

---

### Task 7: GeneratorPage

**Files:**
- Create: `frontend/src/pages/GeneratorPage.tsx`

- [ ] **Step 1: Implement GeneratorPage**

```tsx
// frontend/src/pages/GeneratorPage.tsx
import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  GenerateRequest, Feature, LoaderType, Encryption,
  ALL_FEATURES, generate
} from '../api/generate'
import OpsecFeatures from '../components/OpsecFeatures'
import AppDomainConfig from '../components/AppDomainConfig'
import PeMetadata from '../components/PeMetadata'
import { useAuth } from '../store/auth'

const DEFAULT_PE = {
  company_name:      'Microsoft Corporation',
  file_description:  'Host Process for Windows Services',
  product_name:      'Microsoft Windows Operating System',
  file_version:      '10.0.19041.1',
  original_filename: 'svchost.exe',
  legal_copyright:   '© Microsoft Corporation. All rights reserved.',
  sign: false,
}

const DEFAULT_APPDOMAIN = {
  clr_version:     'v4.0.30319',
  net_version:     '4.0',
  appdomain_type:  '',
  target_assembly: '',
}

export default function GeneratorPage() {
  const navigate   = useNavigate()
  const { logout } = useAuth()

  const [loaderType,  setLoaderType]  = useState<LoaderType>('Binary')
  const [encryption,  setEncryption]  = useState<Encryption>('Aes256')
  const [features,    setFeatures]    = useState<Feature[]>([
    'DirectSyscall', 'AmsiHwbp', 'EtwHwbp', 'SleepEncrypt', 'StackSpoof',
  ])
  const [shellcodeHex, setShellcodeHex] = useState('')
  const [keyHex,        setKeyHex]      = useState('')
  const [ivHex,         setIvHex]       = useState('')
  const [peEnabled,     setPeEnabled]   = useState(false)
  const [peConfig,      setPeConfig]    = useState(DEFAULT_PE)
  const [adConfig,      setAdConfig]    = useState(DEFAULT_APPDOMAIN)
  const [submitting,    setSubmitting]  = useState(false)
  const [error,         setError]       = useState<string | null>(null)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      const req: GenerateRequest = {
        loader_type:        loaderType,
        features,
        encryption,
        shellcode_hex:      shellcodeHex.replace(/\s+/g, ''),
        key_hex:            keyHex.replace(/\s+/g, ''),
        iv_hex:             ivHex.replace(/\s+/g, ''),
        pe_config:          peEnabled ? peConfig : undefined,
        appdomain_config:   loaderType === 'AppDomain' ? adConfig : undefined,
      }
      const { job_id } = await generate(req)
      navigate(`/job/${job_id}`)
    } catch (err: any) {
      setError(err?.response?.data?.message ?? 'Generation failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen bg-crow-bg">
      {/* Header */}
      <header className="border-b border-crow-border bg-crow-surface/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-6 py-3 flex items-center justify-between">
          <span className="font-bold text-crow-text text-lg tracking-tight">DefCrow</span>
          <button
            onClick={logout}
            className="text-xs text-crow-muted hover:text-crow-text transition"
          >
            Sign out
          </button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8">
        <form onSubmit={handleSubmit} className="space-y-8">

          {/* Loader Type + Encryption */}
          <section className="rounded-2xl border border-crow-border bg-crow-surface p-6 space-y-5">
            <h2 className="text-sm font-semibold uppercase tracking-widest text-crow-muted">
              Loader Configuration
            </h2>

            <div className="grid grid-cols-2 gap-5">
              <div>
                <label className="block text-xs text-crow-muted mb-2">Loader Type</label>
                <div className="grid grid-cols-2 gap-2">
                  {(['Binary', 'Dll', 'AppDomain', 'Injector'] as LoaderType[]).map((t) => (
                    <button
                      key={t} type="button"
                      onClick={() => setLoaderType(t)}
                      className={`rounded-lg border py-2 text-sm font-medium transition
                        ${loaderType === t
                          ? 'border-crow-accent bg-violet-950/30 text-crow-accent'
                          : 'border-crow-border text-crow-muted hover:border-violet-700'}`}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-xs text-crow-muted mb-2">Encryption</label>
                <div className="grid grid-cols-2 gap-2">
                  {(['Aes256', 'Chacha20'] as Encryption[]).map((enc) => (
                    <button
                      key={enc} type="button"
                      onClick={() => setEncryption(enc)}
                      className={`rounded-lg border py-2 text-sm font-medium transition
                        ${encryption === enc
                          ? 'border-crow-accent bg-violet-950/30 text-crow-accent'
                          : 'border-crow-border text-crow-muted hover:border-violet-700'}`}
                    >
                      {enc}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Shellcode + keys */}
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-crow-muted mb-1">
                  Shellcode (hex, no spaces required)
                </label>
                <textarea
                  required
                  rows={4}
                  placeholder="fc4883e4f0e8..."
                  value={shellcodeHex}
                  onChange={(e) => setShellcodeHex(e.target.value)}
                  className="w-full rounded-lg bg-crow-bg border border-crow-border px-3 py-2
                             text-xs font-mono text-crow-text focus:border-crow-accent
                             focus:outline-none resize-none"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-crow-muted mb-1">
                    Key ({encryption === 'Aes256' ? '64' : '64'} hex chars)
                  </label>
                  <input
                    type="text"
                    required
                    placeholder={`${'aa'.repeat(32)}`}
                    value={keyHex}
                    onChange={(e) => setKeyHex(e.target.value)}
                    className="w-full rounded-lg bg-crow-bg border border-crow-border px-3 py-1.5
                               text-xs font-mono text-crow-text focus:border-crow-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs text-crow-muted mb-1">
                    IV / Nonce (32 hex chars)
                  </label>
                  <input
                    type="text"
                    required
                    placeholder={`${'bb'.repeat(16)}`}
                    value={ivHex}
                    onChange={(e) => setIvHex(e.target.value)}
                    className="w-full rounded-lg bg-crow-bg border border-crow-border px-3 py-1.5
                               text-xs font-mono text-crow-text focus:border-crow-accent focus:outline-none"
                  />
                </div>
              </div>
            </div>
          </section>

          {/* OPSEC Features */}
          <section className="rounded-2xl border border-crow-border bg-crow-surface p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-widest text-crow-muted">
                OPSEC Features
              </h2>
              <span className="text-xs text-crow-accent">
                {features.length} / {ALL_FEATURES.length} selected
              </span>
            </div>
            <OpsecFeatures selected={features} onChange={setFeatures} />
          </section>

          {/* AppDomain */}
          {loaderType === 'AppDomain' && (
            <AppDomainConfig value={adConfig} onChange={setAdConfig} />
          )}

          {/* PE Metadata */}
          <PeMetadata
            value={peConfig}
            onChange={setPeConfig}
            enabled={peEnabled}
            onToggle={setPeEnabled}
          />

          {error && (
            <p className="rounded-xl bg-red-950/40 border border-red-800 px-4 py-3
                          text-sm text-crow-danger">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full py-3 rounded-xl bg-crow-accent hover:bg-violet-700
                       text-white font-semibold text-sm transition disabled:opacity-50
                       disabled:cursor-not-allowed shadow-lg shadow-violet-900/20"
          >
            {submitting ? 'Submitting…' : 'Generate Loader'}
          </button>
        </form>
      </main>
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/pages/GeneratorPage.tsx
git commit -m "feat(frontend): GeneratorPage — full loader config form"
```

---

### Task 8: JobStatusPage

**Files:**
- Create: `frontend/src/pages/JobStatusPage.tsx`

- [ ] **Step 1: Write failing test**

```typescript
// frontend/src/pages/__tests__/JobStatusPage.test.tsx
import { render, screen, act } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import JobStatusPage from '../JobStatusPage'
import * as socketHook from '../../hooks/useJobSocket'

describe('JobStatusPage', () => {
  it('shows queued state initially', () => {
    vi.spyOn(socketHook, 'useJobSocket').mockReturnValue({ status: { status: 'queued' } })
    render(
      <MemoryRouter initialEntries={['/job/abc123']}>
        <Routes><Route path="/job/:id" element={<JobStatusPage />} /></Routes>
      </MemoryRouter>
    )
    expect(screen.getByText(/queued/i)).toBeInTheDocument()
  })

  it('shows progress bar while building', () => {
    vi.spyOn(socketHook, 'useJobSocket').mockReturnValue({
      status: { status: 'building', progress: 40, msg: 'Compiling...' }
    })
    render(
      <MemoryRouter initialEntries={['/job/abc123']}>
        <Routes><Route path="/job/:id" element={<JobStatusPage />} /></Routes>
      </MemoryRouter>
    )
    expect(screen.getByText('Compiling...')).toBeInTheDocument()
    expect(screen.getByRole('progressbar')).toBeInTheDocument()
  })

  it('shows download button when done', () => {
    vi.spyOn(socketHook, 'useJobSocket').mockReturnValue({
      status: { status: 'done', download_id: 'xyz789' }
    })
    render(
      <MemoryRouter initialEntries={['/job/abc123']}>
        <Routes><Route path="/job/:id" element={<JobStatusPage />} /></Routes>
      </MemoryRouter>
    )
    expect(screen.getByRole('link', { name: /download/i })).toBeInTheDocument()
  })

  it('shows error message on failure', () => {
    vi.spyOn(socketHook, 'useJobSocket').mockReturnValue({
      status: { status: 'error', msg: 'rustc: linker not found' }
    })
    render(
      <MemoryRouter initialEntries={['/job/abc123']}>
        <Routes><Route path="/job/:id" element={<JobStatusPage />} /></Routes>
      </MemoryRouter>
    )
    expect(screen.getByText(/linker not found/i)).toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Run test — verify failure**

```bash
cd frontend && npm run test -- --run src/pages/__tests__/JobStatusPage.test.tsx
```

Expected: FAIL

- [ ] **Step 3: Implement JobStatusPage**

```tsx
// frontend/src/pages/JobStatusPage.tsx
import { useParams, Link } from 'react-router-dom'
import { useJobSocket } from '../hooks/useJobSocket'

export default function JobStatusPage() {
  const { id }     = useParams<{ id: string }>()
  const { status } = useJobSocket(id ?? null)

  const progress = status?.status === 'building' ? (status.progress ?? 0) : 0

  return (
    <div className="min-h-screen bg-crow-bg flex items-center justify-center">
      <div className="w-full max-w-lg rounded-2xl border border-crow-border bg-crow-surface p-8 space-y-6">

        <div className="text-center">
          <h1 className="text-xl font-bold text-crow-text">Build Job</h1>
          <p className="text-xs text-crow-muted font-mono mt-1">{id}</p>
        </div>

        {/* Status indicator */}
        {!status && (
          <div className="flex items-center gap-3 justify-center">
            <div className="w-4 h-4 rounded-full bg-crow-muted animate-pulse" />
            <span className="text-crow-muted text-sm">Connecting…</span>
          </div>
        )}

        {status?.status === 'queued' && (
          <div className="flex items-center gap-3 justify-center">
            <div className="w-4 h-4 rounded-full bg-yellow-400 animate-pulse" />
            <span className="text-yellow-400 text-sm">Queued</span>
          </div>
        )}

        {status?.status === 'building' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-crow-text">{status.msg}</span>
              <span className="text-sm text-crow-accent font-mono">{status.progress}%</span>
            </div>
            <div
              role="progressbar"
              aria-valuenow={status.progress}
              aria-valuemin={0}
              aria-valuemax={100}
              className="w-full h-2 rounded-full bg-crow-border overflow-hidden"
            >
              <div
                className="h-full rounded-full bg-crow-accent transition-all duration-500"
                style={{ width: `${status.progress}%` }}
              />
            </div>
          </div>
        )}

        {status?.status === 'done' && (
          <div className="space-y-4 text-center">
            <div className="flex items-center gap-3 justify-center">
              <div className="w-4 h-4 rounded-full bg-crow-success" />
              <span className="text-crow-success text-sm font-medium">Build complete</span>
            </div>
            <a
              href={`/api/download/${status.download_id}`}
              download
              role="link"
              className="inline-flex items-center gap-2 px-6 py-3 rounded-xl
                         bg-crow-success hover:bg-green-700 text-white font-medium
                         text-sm transition shadow-lg shadow-green-900/20"
            >
              Download Loader
            </a>
          </div>
        )}

        {status?.status === 'error' && (
          <div className="rounded-xl bg-red-950/40 border border-red-800 p-4">
            <p className="text-crow-danger text-sm font-medium mb-2">Build Failed</p>
            <pre className="text-xs text-crow-muted whitespace-pre-wrap font-mono leading-relaxed">
              {status.msg}
            </pre>
          </div>
        )}

        <div className="text-center">
          <Link to="/" className="text-xs text-crow-muted hover:text-crow-text transition">
            ← Back to Generator
          </Link>
        </div>
      </div>
    </div>
  )
}
```

- [ ] **Step 4: Run tests — verify pass**

```bash
cd frontend && npm run test -- --run src/pages/__tests__/JobStatusPage.test.tsx
```

Expected: 4 tests pass

- [ ] **Step 5: Run full test suite**

```bash
cd frontend && npm run test -- --run
```

Expected: all tests pass

- [ ] **Step 6: Build for production**

```bash
cd frontend && npm run build
```

Expected: `dist/` created with `index.html` + hashed JS/CSS assets

- [ ] **Step 7: Commit**

```bash
git add frontend/src/pages/JobStatusPage.tsx
git commit -m "feat(frontend): JobStatusPage — progress bar + download button"
```

---

### Task 9: End-to-End Dev Server Smoke Test

**Files:** None (verification only)

- [ ] **Step 1: Start Axum backend (terminal 1)**

```bash
DEFCROW_PASSWORD_HASH=$(echo 'testpassword' | cargo run -p defcrow-cli -- hash-password 2>/dev/null | head -1) \
DEFCROW_SESSION_SECRET=dev_secret \
DEFCROW_PORT=8080 \
DEFCROW_WORKSPACE=. \
RUST_LOG=info \
cargo run -p web-server
```

Expected: `DefCrow server listening on 0.0.0.0:8080` (may take ~90s first time for scaffold)

- [ ] **Step 2: Start Vite dev server (terminal 2)**

```bash
cd frontend && npm run dev
```

Expected: `Local: http://localhost:5173`

- [ ] **Step 3: Smoke test via curl**

```bash
# Health check
curl -s http://localhost:8080/api/health

# Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"testpassword"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "Token: $TOKEN"

# Generate (tiny NOP shellcode test)
JOB=$(curl -s -X POST http://localhost:8080/api/generate \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "loader_type": "Binary",
    "features":    ["AmsiHwbp"],
    "encryption":  "Aes256",
    "shellcode_hex": "9090",
    "key_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "iv_hex":  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])")

echo "Job ID: $JOB"

# Poll status
curl -s http://localhost:8080/api/jobs/$JOB \
  -H "Authorization: Bearer $TOKEN"
```

Expected: `{"status":"queued"}` or `{"status":"building",...}`

- [ ] **Step 4: Open browser**

Open `http://localhost:5173` in a browser.

Expected checklist:
- [ ] Redirect to `/login` (not authenticated)
- [ ] Login form renders with username + password fields
- [ ] Submit admin / testpassword → redirect to `/`
- [ ] GeneratorPage renders with all 4 loader type buttons
- [ ] All 15 OPSEC toggles visible, categorized
- [ ] Selecting AppDomain shows AppDomainConfig panel
- [ ] PE Metadata toggle shows/hides fields
- [ ] Submit form → redirects to `/job/:id`
- [ ] Progress bar animates as build proceeds
- [ ] Download button appears on completion
- [ ] Error message with stderr on build failure

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: DefCrow frontend complete — E2E smoke test passed"
```

---

## Summary

After completing all 9 tasks:
- Single-page React app with login, generator, and job status pages
- 15 OPSEC feature toggles categorized by type
- AppDomain config panel (CLR version, DM type, target assembly)
- PE metadata spoofing with presets + osslsigncode signing toggle
- WebSocket real-time progress — queued → building → done → download
- All Vite proxying configured for dev (`:5173` → `:8080`)
- Production build outputs to `frontend/dist/` served by Axum via `ServeDir`

**Defcrow is complete. All 3 plans implemented.**
