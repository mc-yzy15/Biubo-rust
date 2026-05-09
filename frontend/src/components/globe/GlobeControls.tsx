import { useTranslation } from 'react-i18next'

interface GlobeControlsProps {
  autoRotate: boolean
  paused: boolean
  speed: number
  onToggleRotate: () => void
  onTogglePause: () => void
  onSpeedChange: (speed: number) => void
  onClear: () => void
}

export function GlobeControls({ autoRotate, paused, speed, onToggleRotate, onTogglePause, onSpeedChange, onClear }: GlobeControlsProps) {
  const { t } = useTranslation()

  return (
    <div className="g-controls">
      <button
        className={`ctrl-btn${autoRotate ? ' active' : ''}`}
        onClick={onToggleRotate}
      >
        {t('globe.autoRotate')}
      </button>
      <div className="ctrl-sep" />
      <span className="speed-label">{t('globe.speed')}</span>
      <input
        type="range"
        min={1}
        max={10}
        value={speed}
        onChange={e => onSpeedChange(parseInt(e.target.value))}
        style={{ accentColor: 'var(--accent)' }}
      />
      <div className="ctrl-sep" />
      <button
        className={`ctrl-btn${paused ? ' active' : ''}`}
        onClick={onTogglePause}
      >
        {paused ? t('globe.resume') : t('globe.pause')}
      </button>
      <div className="ctrl-sep" />
      <button className="ctrl-btn danger" onClick={onClear}>
        {t('logs.clear')}
      </button>
    </div>
  )
}
