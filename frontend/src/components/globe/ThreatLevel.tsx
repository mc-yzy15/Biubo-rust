import { useTranslation } from 'react-i18next'

interface ThreatLevelProps {
  total: number
}

export function ThreatLevel({ total }: ThreatLevelProps) {
  const { t } = useTranslation()

  if (total === 0) {
    return (
      <div className="g-card">
        <div className="g-card-title">{t('globe.threatLevel')}</div>
        <div style={{ background: 'rgba(255,58,58,0.12)', border: '1px solid rgba(255,58,58,0.25)', borderRadius: 4, padding: 10, textAlign: 'center', marginBottom: 10 }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 22, color: 'var(--green)', fontWeight: 700 }}>
            {t('common.low')}
          </div>
          <div style={{ fontSize: 9, color: 'var(--dim)', letterSpacing: '1.5px', textTransform: 'uppercase', marginTop: 2 }}>
            {t('globe.currentLevel')}
          </div>
        </div>
        <div style={{ height: 5, background: 'rgba(255,255,255,0.05)', borderRadius: 3, overflow: 'hidden' }}>
          <div style={{ height: '100%', width: '0%', background: 'linear-gradient(90deg,var(--accent2),var(--red))', borderRadius: 3, transition: 'width 1s ease' }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
          <span style={{ fontSize: 8, color: 'var(--dim)', letterSpacing: '1px', textTransform: 'uppercase' }}>{t('common.low')}</span>
          <span style={{ fontSize: 8, color: 'var(--dim)', letterSpacing: '1px', textTransform: 'uppercase' }}>{t('common.critical')}</span>
        </div>
      </div>
    )
  }

  const ratio = Math.min(1, total / 500)
  const level = ratio < 0.3 ? 'common.low' : ratio < 0.6 ? 'common.medium' : ratio < 0.85 ? 'common.high' : 'common.critical'
  const color = ratio < 0.3 ? 'var(--green)' : ratio < 0.6 ? 'var(--yellow)' : ratio < 0.85 ? '#ff7700' : 'var(--red)'

  return (
    <div className="g-card">
      <div className="g-card-title">{t('globe.threatLevel')}</div>
      <div style={{ background: 'rgba(255,58,58,0.12)', border: '1px solid rgba(255,58,58,0.25)', borderRadius: 4, padding: 10, textAlign: 'center', marginBottom: 10 }}>
        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 22, color, fontWeight: 700 }}>
          {t(level)}
        </div>
        <div style={{ fontSize: 9, color: 'var(--dim)', letterSpacing: '1.5px', textTransform: 'uppercase', marginTop: 2 }}>
          {t('globe.currentLevel')}
        </div>
      </div>
      <div style={{ height: 5, background: 'rgba(255,255,255,0.05)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${ratio * 100}%`, background: 'linear-gradient(90deg,var(--accent2),var(--red))', borderRadius: 3, transition: 'width 1s ease' }} />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
        <span style={{ fontSize: 8, color: 'var(--dim)', letterSpacing: '1px', textTransform: 'uppercase' }}>{t('common.low')}</span>
        <span style={{ fontSize: 8, color: 'var(--dim)', letterSpacing: '1px', textTransform: 'uppercase' }}>{t('common.critical')}</span>
      </div>
    </div>
  )
}
