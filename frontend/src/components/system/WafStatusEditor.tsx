import { useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Card } from '../ui/Card'
import type { WafStatusInfo } from '../../hooks/useSystemStatus'

export interface WafStatusEditorProps {
  wafStatus: WafStatusInfo | null
  host: string | null
  onSaved: () => void
  showToast: (message: string, type: 'ok' | 'err') => void
}

export function WafStatusEditor({ wafStatus, host, onSaved, showToast }: WafStatusEditorProps) {
  const { t } = useTranslation()
  const [status, setStatus] = useState(wafStatus?.site?.status || '')
  const [saving, setSaving] = useState(false)

  const handleSave = useCallback(async () => {
    if (!host) {
      showToast(t('ipManage.selectHost'), 'err')
      return
    }

    setSaving(true)
    try {
      const res = await fetch('/biubo-cgi/info/biubo/setting', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      })

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`)
      }

      const json = await res.json()
      if (json.status === 'success') {
        showToast(t('system.saveSuccess'), 'ok')
        onSaved()
      } else {
        showToast(json.msg || t('system.saveFailed'), 'err')
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : t('system.saveFailed')
      showToast(msg, 'err')
    } finally {
      setSaving(false)
    }
  }, [host, status, showToast, t, onSaved])

  const statusColor = status === 'on' ? 'var(--green)' : status === 'off' ? 'var(--red)' : 'var(--yellow)'

  const infoRows = [
    { key: t('dashboard.domain'), value: wafStatus?.site?.domain || '-' },
    { key: t('dashboard.status'), value: status, isSelect: true },
    { key: t('dashboard.description'), value: wafStatus?.site?.description || '-' },
    { key: t('dashboard.createdAt'), value: wafStatus?.site?.created_at || '-' },
  ]

  return (
    <Card title={t('system.wafStatus')}>
      {infoRows.map((row, idx) => (
        <div className="detail-row" key={idx}>
          <div className="detail-key">{row.key}</div>
          <div className="detail-val">
            {row.isSelect ? (
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                style={{
                  background: 'rgba(0, 100, 180, 0.15)',
                  border: '1px solid var(--border)',
                  borderRadius: 4,
                  padding: '2px 8px',
                  color: statusColor,
                  fontSize: 13,
                  fontFamily: "'Share Tech Mono', monospace",
                  outline: 'none',
                  cursor: 'pointer',
                }}
              >
                <option value="on" style={{ background: 'var(--sidebar)', color: 'var(--green)' }}>on</option>
                <option value="off" style={{ background: 'var(--sidebar)', color: 'var(--red)' }}>off</option>
                <option value="unknown" style={{ background: 'var(--sidebar)', color: 'var(--yellow)' }}>unknown</option>
              </select>
            ) : (
              <span style={row.key === t('dashboard.status') ? { color: statusColor } : undefined}>
                {row.value}
              </span>
            )}
          </div>
        </div>
      ))}

      <div style={{ marginTop: 12, textAlign: 'right' }}>
        <button
          className="tb-btn"
          onClick={handleSave}
          disabled={saving}
          style={{ opacity: saving ? 0.5 : 1, cursor: saving ? 'not-allowed' : 'pointer' }}
        >
          {saving ? '...' : t('system.save')}
        </button>
      </div>
    </Card>
  )
}
