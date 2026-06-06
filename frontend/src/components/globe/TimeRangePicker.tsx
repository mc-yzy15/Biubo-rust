import { useState } from 'react'
import { useTranslation } from 'react-i18next'

interface TimeRangePickerProps {
  onReload: (from: string, to: string) => void
}

export function TimeRangePicker({ onReload }: TimeRangePickerProps) {
  const { t } = useTranslation()
  const today = new Date()
  const todayStr = today.toISOString().slice(0, 10)
  const fromD = new Date(today)
  fromD.setDate(fromD.getDate() - 29)
  const fromStr = fromD.toISOString().slice(0, 10)

  const [dateFrom, setDateFrom] = useState(fromStr)
  const [dateTo, setDateTo] = useState(todayStr)

  const handleReload = () => {
    onReload(dateFrom, dateTo)
  }

  return (
    <div className="g-card">
      <div className="g-card-title">{t('globe.timeRange')}</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{ fontSize: 9, color: 'var(--dim)', letterSpacing: '1px', textTransform: 'uppercase', width: 24, flexShrink: 0 }}>{t('globe.from')}</span>
          <input
            type="date"
            value={dateFrom}
            onChange={e => setDateFrom(e.target.value)}
            style={{ flex: 1, background: 'rgba(0,100,180,0.1)', border: '1px solid var(--border)', borderRadius: 4, padding: '5px 8px', color: 'var(--text)', fontSize: 11, outline: 'none' }}
          />
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{ fontSize: 9, color: 'var(--dim)', letterSpacing: '1px', textTransform: 'uppercase', width: 24, flexShrink: 0 }}>{t('globe.to')}</span>
          <input
            type="date"
            value={dateTo}
            onChange={e => setDateTo(e.target.value)}
            style={{ flex: 1, background: 'rgba(0,100,180,0.1)', border: '1px solid var(--border)', borderRadius: 4, padding: '5px 8px', color: 'var(--text)', fontSize: 11, outline: 'none' }}
          />
        </div>
        <button
          onClick={handleReload}
          style={{ background: 'rgba(0,200,255,0.1)', border: '1px solid var(--accent)', borderRadius: 4, padding: 6, color: 'var(--accent)', fontSize: 11, cursor: 'pointer', fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, letterSpacing: 1 }}
        >
          {t('globe.reloadMap')}
        </button>
      </div>
    </div>
  )
}
