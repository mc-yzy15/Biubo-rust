import React, { useCallback } from 'react'
import { useApp } from '../../context/AppContext'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'

export function AppLayout({ children }: { children: React.ReactNode }) {
  const { sidebarOpen, setSidebarOpen } = useApp()

  const handleSidebarClose = useCallback(() => {
    setSidebarOpen(false)
  }, [setSidebarOpen])

  return (
    <>
      <div className={`sidebar-overlay${sidebarOpen ? ' open' : ''}`} onClick={handleSidebarClose} />
      <Sidebar onCloseMobile={handleSidebarClose} />
      <div className="main-area">
        <Topbar />
        <div className="content" id="content">
          {children}
        </div>
      </div>
    </>
  )
}
