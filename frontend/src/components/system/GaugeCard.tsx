export interface GaugeCardProps {
  label: string
  percent: number
  subtitle?: string
  colorVariant: 'blue' | 'red' | 'green'
}

export function GaugeCard({ label, percent, subtitle, colorVariant }: GaugeCardProps) {
  const clampedPercent = Math.min(100, Math.max(0, percent))

  return (
    <div className="card">
      <div className="gauge-wrap">
        <div className="gauge-val">{clampedPercent.toFixed(1)}%</div>
        <div className="progress-bar">
          <div
            className={`progress-fill ${colorVariant}`}
            style={{ width: `${clampedPercent}%` }}
          />
        </div>
        <div className="gauge-label">{label}</div>
        {subtitle && (
          <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4, fontFamily: "'Share Tech Mono', monospace" }}>
            {subtitle}
          </div>
        )}
      </div>
    </div>
  )
}
