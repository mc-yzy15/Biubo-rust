import { useTranslation } from 'react-i18next'

interface ThreatStatsProps {
  total: number
  ratePerMin: number
  blocked: number
  critical: number
}

export function ThreatStats({ total, ratePerMin, blocked, critical }: ThreatStatsProps) {
  const { t } = useTranslation()

  return (
    <div className="g-card">
      <div className="g-card-title">{t('globe.threatStats')}</div>
      <div className="stats-grid">
        <div className="stat-item">
          <div className="val red">{total.toLocaleString()}</div>
          <div className="lbl">{t('globe.totalAttacks')}</div>
        </div>
        <div className="stat-item">
          <div className="val">{ratePerMin}</div>
          <div className="lbl">{t('globe.perMinute')}</div>
        </div>
        <div className="stat-item">
          <div className="val green">{blocked.toLocaleString()}</div>
          <div className="lbl">{t('globe.blocked')}</div>
        </div>
        <div className="stat-item">
          <div className="val" style={{ color: 'var(--yellow)' }}>{critical.toLocaleString()}</div>
          <div className="lbl">{t('globe.critical')}</div>
        </div>
      </div>
    </div>
  )
}
