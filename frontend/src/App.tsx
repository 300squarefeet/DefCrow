import { Routes, Route } from 'react-router-dom'
import { AuthProvider } from './store/auth'
import ProtectedRoute from './components/ProtectedRoute'
import LoginPage      from './pages/LoginPage'
import GeneratorPage  from './pages/GeneratorPage'
import JobStatusPage  from './pages/JobStatusPage'
import SettingsPage   from './pages/SettingsPage'

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login"    element={<LoginPage />} />
        <Route path="/"         element={<ProtectedRoute><GeneratorPage /></ProtectedRoute>} />
        <Route path="/job/:id"  element={<ProtectedRoute><JobStatusPage /></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
      </Routes>
    </AuthProvider>
  )
}
