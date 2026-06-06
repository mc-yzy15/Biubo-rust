import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './i18n'
import { AppProvider } from './context/AppContext'
import { ToastProvider } from './context/ToastContext'
import App from './App'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AppProvider>
      <ToastProvider>
        <App />
      </ToastProvider>
    </AppProvider>
  </StrictMode>,
)
