import React, { useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { BlacklistEntry } from '../../hooks/useIPManager'

interface BlacklistPanelProps {
  entries: BlacklistEntry[]
  loading: boolean
  onAdd: (ip: string, reason: string) => Promise<boolean>
  onUnban: (ip: string) => Promise<boolean>
}

export function BlacklistPanel({ entries, loading, onAdd, onUnban }: BlacklistPanelProps) {
  const { t } = useTranslation()
  const [ip, setIp] = useState('')
  const [reason, setReason] = useState('')

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault()
    if (!ip.trim()) return
    const success = await onAdd(ip.trim(), reason.trim() || t('ipManage.manualBan'))
    if (success) {
      setIp('')
      setReason('')
    }
  }, [ip, reason, onAdd, t])

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--dim)' }}>
        {t('topbar.loading')}
      </div>
    )
  }

  return (
    <>
      <form className="add-form" onSubmit={handleSubmit}>
        <input
          type="text"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder={t('ipManage.ipAddress')}
          style={{ flex: 1 }}
        />
        <input
          type="text"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={t('ipManage.reason')}
          style={{ flex: 1 }}
        />
        <button type="submit">{t('ipManage.add')}</button>
      </form>

      <div>
        {entries.length === 0 ? (
          <div style={{ color: 'var(--dim)', fontSize: 12, padding: 12 }}>
            {t('ipManage.noBannedIPs')}
          </div>
        ) : (
          entries.map((entry) => (
            <div key={entry.ip} className="ip-row">
              <div className="ip-addr">{entry.ip}</div>
              <div className="ip-meta">
                {t(entry.reason)}
                {entry.banned_at ? ` · ${entry.banned_at}` : ''}
              </div>
              <button className="ip-del" onClick={() => onUnban(entry.ip)}>
                {t('ipManage.unban')}
              </button>
            </div>
          ))
        )}
      </div>
    </>
  )
}
