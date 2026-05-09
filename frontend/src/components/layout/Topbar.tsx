import { useState, useEffect, useCallback, useRef } from 'react'
import { useApp } from '../../context/AppContext'
import { useTranslation } from 'react-i18next'
import { api } from '../../api/client'

interface HostOption {
  host: string
  port: number
}

export function Topbar() {
  const { hosts, currentHost, setCurrentHost, language, setLanguage, setHosts } = useApp()
  const { t, i18n } = useTranslation()
  const [time, setTime] = useState(new Date().toLocaleTimeString())
  const [hostDropdownOpen, setHostDropdownOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toLocaleTimeString())
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    api.get<HostOption[]>('/biubo/dashboard/proxy-map')
      .then((data) => {
        if (Array.isArray(data)) {
          setHosts(data)
        } else if (data && typeof data === 'object') {
          const list = Object.entries(data).map(([host, port]) => ({
            host,
            port: typeof port === 'number' ? port : 443,
          }))
          setHosts(list)
        }
      })
      .catch(() => {})
  }, [setHosts])

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setHostDropdownOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleHostChange = useCallback(
    (host: string) => {
      setCurrentHost(host)
      setHostDropdownOpen(false)
      const protocol = window.location.protocol
      window.location.href = `${protocol}//${host}/biubo/dashboard`
    },
    [setCurrentHost]
  )

  const handleLangToggle = useCallback(() => {
    const newLang = language === 'zh' ? 'en' : 'zh'
    setLanguage(newLang)
    i18n.changeLanguage(newLang)
    localStorage.setItem('biubo_lang', newLang)
  }, [language, setLanguage, i18n])

  const handleLogout = useCallback(() => {
    fetch('/dashboard/api/logout', { method: 'POST' })
      .catch(() => {})
      .finally(() => {
        window.location.href = '/dashboard/login'
      })
  }, [])

  const handleRefresh = useCallback(() => {
    window.location.reload()
  }, [])

  return (
    <header className="topbar">
      <div className="tb-left">
        <span className="live-dot">{t('topbar.live')}</span>
        <span className="tb-time">{time}</span>

        <div className="tb-host" ref={dropdownRef} style={{ position: 'relative' }}>
          <button
            className="tb-btn"
            onClick={() => setHostDropdownOpen((v) => !v)}
          >
            {currentHost || (hosts.length > 0 ? hosts[0].host : t('topbar.loading'))}
          </button>
          {hostDropdownOpen && hosts.length > 0 && (
            <div
              style={{
                position: 'absolute',
                top: '100%',
                left: 0,
                marginTop: 4,
                background: 'rgba(2, 15, 35, 0.98)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                padding: '6px 0',
                minWidth: 180,
                zIndex: 999,
                backdropFilter: 'blur(10px)',
              }}
            >
              {hosts.map((h) => (
                <div
                  key={h.host}
                  style={{
                    padding: '8px 16px',
                    cursor: 'pointer',
                    color: currentHost === h.host ? 'var(--accent)' : 'var(--text)',
                    fontSize: 14,
                    fontFamily: "'Share Tech Mono', monospace",
                    transition: 'all .15s',
                  }}
                  onClick={() => handleHostChange(h.host)}
                  onMouseEnter={(e) => {
                    ;(e.target as HTMLElement).style.background = 'rgba(0, 200, 255, 0.08)'
                  }}
                  onMouseLeave={(e) => {
                    ;(e.target as HTMLElement).style.background = 'transparent'
                  }}
                >
                  {h.host}{h.port !== 443 && h.port !== 80 ? `:${h.port}` : ''}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="tb-right">
        <button className="tb-btn" onClick={handleLangToggle}>
          {language === 'zh' ? '中文' : 'EN'}
        </button>
        <button className="tb-btn" onClick={handleRefresh}>
          {t('topbar.refresh')}
        </button>
        <button className="tb-btn" onClick={handleLogout}>
          {t('topbar.logout')}
        </button>
      </div>
    </header>
  )
}
