import axios from 'axios'

export const client = axios.create({ baseURL: '/api', timeout: 30_000 })

client.interceptors.request.use((config) => {
  const token = localStorage.getItem('defcrow_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

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
