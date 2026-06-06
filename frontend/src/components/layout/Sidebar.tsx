import React, { useCallback } from 'react'
import { useApp } from '../../context/AppContext'
import { useTranslation } from 'react-i18next'
import type { TabId } from '../../types'

interface NavGroup {
  sectionKey: string
  items: { tab: TabId; icon: React.ReactNode; labelKey: string }[]
}

const NAV_GROUPS: NavGroup[] = [
  {
    sectionKey: 'monitor',
    items: [
      {
        tab: 'globe',
        labelKey: 'globe',
        icon: (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <path d="M2 12h20" />
            <path d="M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10A15 15 0 0 1 12 2z" />
          </svg>
        ),
      },
      {
        tab: 'dashboard',
        labelKey: 'dashboard',
        icon: (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="3" width="7" height="7" rx="1" />
            <rect x="14" y="3" width="7" height="7" rx="1" />
            <rect x="3" y="14" width="7" height="7" rx="1" />
            <rect x="14" y="14" width="7" height="7" rx="1" />
          </svg>
        ),
      },
    ],
  },
  {
    sectionKey: 'management',
    items: [
      {
        tab: 'logs',
        labelKey: 'logs',
        icon: (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14,2 14,8 20,8" />
            <line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" />
            <polyline points="10,9 9,9 8,9" />
          </svg>
        ),
      },
      {
        tab: 'ipmanage',
        labelKey: 'ipAccess',
        icon: (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777z" />
            <path d="M15.5 4.5a5.5 5.5 0 0 1 0 7.778" />
          </svg>
        ),
      },
    ],
  },
  {
    sectionKey: 'system',
    items: [
      {
        tab: 'system',
        labelKey: 'systemInfo',
        icon: (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
            <line x1="8" y1="21" x2="16" y2="21" />
            <line x1="12" y1="17" x2="12" y2="21" />
          </svg>
        ),
      },
      {
        tab: 'plugins',
        labelKey: 'plugins',
        icon: (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
            <polyline points="3.27,6.96 12,12.01 20.73,6.96" />
            <line x1="12" y1="22.08" x2="12" y2="12" />
          </svg>
        ),
      },
      {
        tab: 'settings',
        labelKey: 'settings',
        icon: (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
          </svg>
        ),
      },
    ],
  },
]

interface SidebarProps {
  onCloseMobile?: () => void
}

export function Sidebar({ onCloseMobile }: SidebarProps) {
  const { currentTab, setTab, sidebarOpen } = useApp()
  const { t } = useTranslation()

  const handleNav = useCallback(
    (tab: TabId) => {
      setTab(tab)
      onCloseMobile?.()
    },
    [setTab, onCloseMobile]
  )

  return (
    <nav className={`sidebar${sidebarOpen ? ' open' : ''}`}>
      <div className="sb-logo">
        <div className="sb-logo-icon">⬡</div>
        <h1>Biubo WAF</h1>
      </div>

      {NAV_GROUPS.map((group) => (
        <React.Fragment key={group.sectionKey}>
          <div className="sb-section">{t(`sidebar.${group.sectionKey}`)}</div>
          {group.items.map((item) => (
            <div
              key={item.tab}
              className={`sb-item ${currentTab === item.tab ? 'active' : ''}`.trim()}
              onClick={() => handleNav(item.tab)}
            >
              {item.icon}
              <span>{t(`sidebar.${item.labelKey}`)}</span>
            </div>
          ))}
        </React.Fragment>
      ))}

      <div className="sb-spacer" />

      <div
        className="sb-item"
        onClick={() => {
          fetch('/dashboard/api/logout', { method: 'POST' })
            .catch(() => {})
            .finally(() => {
              window.location.href = '/dashboard/login'
            })
        }}
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
          <polyline points="16,17 21,12 16,7" />
          <line x1="21" y1="12" x2="9" y2="12" />
        </svg>
        <span>{t('sidebar.logout')}</span>
      </div>
    </nav>
  )
}
