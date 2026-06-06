import { useTranslation } from 'react-i18next'

interface AttackTypeBarsProps {
  typeCounts: Record<string, number>
}

const TYPE_COLOR_MAP: Record<string, string> = {
  'hacker': '#ff3a3a', 'sql': '#ff7700', 'xss': '#ffd700', 'ddos': '#ff3aff',
  'bot': '#aa00ff', 'scan': '#00c8ff', 'brute': '#00ff8c', 'upload': '#ff5588',
  'rce': '#ff3a3a', 'lfi': '#ff7700', 'normal': '#00c8ff',
}

const TYPE_COLORS = ['#ff3a3a', '#ff7700', '#ffd700', '#ff3aff', '#aa00ff', '#00c8ff', '#00ff8c', '#ff5588']

export function AttackTypeBars({ typeCounts }: AttackTypeBarsProps) {
  const { t } = useTranslation()

  const total = Object.values(typeCounts).reduce((a, b) => a + b, 0) || 1
  const sorted = Object.entries(typeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)

  return (
    <div className="g-card">
      <div className="g-card-title">{t('globe.attackTypes')}</div>
      {sorted.length > 0 ? (
        sorted.map(([type, count], i) => {
          const typeKey = type.toLowerCase().replace(/[^a-z]/g, '')
          const color = TYPE_COLOR_MAP[typeKey] || TYPE_COLORS[i % TYPE_COLORS.length]
          return (
            <div key={type} className="type-bar-row">
              <div className="type-label">{type.slice(0, 8)}</div>
              <div className="type-bar-bg">
                <div
                  className="type-bar-fill"
                  style={{ width: `${(count / total) * 100}%`, background: color }}
                />
              </div>
              <div className="type-count">{count}</div>
            </div>
          )
        })
      ) : (
        <div style={{ color: 'var(--dim)', fontSize: 11 }}>{t('globe.waitingForData')}</div>
      )}
    </div>
  )
}
