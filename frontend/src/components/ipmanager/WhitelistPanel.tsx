import React, { useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { WhitelistEntry } from '../../hooks/useIPManager'

interface WhitelistPanelProps {
  entries: WhitelistEntry[]
  loading: boolean
  onAdd: (ip: string, note: string) => Promise<boolean>
  onRemove: (ip: string) => Promise<boolean>
}

export function WhitelistPanel({ entries, loading, onAdd, onRemove }: WhitelistPanelProps) {
  const { t } = useTranslation()
  const [ip, setIp] = useState('')
  const [note, setNote] = useState('')

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault()
    if (!ip.trim()) return
    const success = await onAdd(ip.trim(), note.trim() || t('ipManage.manualAdd'))
    if (success) {
      setIp('')
      setNote('')
    }
  }, [ip, note, onAdd, t])

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
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder={t('ipManage.note')}
          style={{ flex: 1 }}
        />
        <button type="submit">{t('ipManage.add')}</button>
      </form>

      <div>
        {entries.length === 0 ? (
          <div style={{ color: 'var(--dim)', fontSize: 12, padding: 12 }}>
            {t('ipManage.noWhitelistIPs')}
          </div>
        ) : (
          entries.map((entry) => (
            <div key={entry.ip} className="ip-row">
              <div className="ip-addr">{entry.ip}</div>
              <div className="ip-meta">{t(entry.note)}</div>
              <button className="ip-del" onClick={() => onRemove(entry.ip)}>
                {t('ipManage.remove')}
              </button>
            </div>
          ))
        )}
      </div>
    </>
  )
}
