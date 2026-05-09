import React from 'react'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'

export function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <Sidebar />
      <div className="main-area">
        <Topbar />
        <div className="content" id="content">
          {children}
        </div>
      </div>
    </>
  )
}
