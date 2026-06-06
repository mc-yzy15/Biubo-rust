import React, { createContext, useState, useCallback } from 'react'
import type { AppContextType, TabId, HostInfo } from '../types'

export const AppContext = createContext<AppContextType | undefined>(undefined)

export interface AppProviderProps {
  children: React.ReactNode
}

export function AppProvider({ children }: AppProviderProps) {
  const [currentTab, setTab] = useState<TabId>('dashboard')
  const [hosts, setHosts] = useState<HostInfo[]>([])
  const [currentHost, setCurrentHostState] = useState<string | null>(null)
  const [language, setLanguage] = useState<string>('zh')
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const setCurrentHost = useCallback((host: string) => {
    setCurrentHostState(host)
  }, [])

  const value: AppContextType = {
    currentTab,
    hosts,
    currentHost,
    language,
    setTab,
    setHosts,
    setCurrentHost,
    setLanguage,
    sidebarOpen,
    setSidebarOpen,
  }

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>
}

export function useApp() {
  const ctx = React.useContext(AppContext)
  if (!ctx) throw new Error('useApp must be used within AppProvider')
  return ctx
}
