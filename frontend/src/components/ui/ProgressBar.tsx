export interface ProgressBarProps {
  variant?: 'blue' | 'red' | 'green'
  value: number
  className?: string
}

export function ProgressBar({ variant = 'blue', value, className = '' }: ProgressBarProps) {
  return (
    <div className={`progress-bar ${className}`.trim()}>
      <div className={`progress-fill ${variant}`} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
    </div>
  )
}
