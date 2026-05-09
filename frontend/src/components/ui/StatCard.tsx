export interface StatCardProps {
  variant: 'blue' | 'red' | 'green' | 'yellow'
  label: string
  value: string | number
}

export function StatCard({ variant, label, value }: StatCardProps) {
  return (
    <div className={`stat-card ${variant}`}>
      <div className="stat-label">{label}</div>
      <div className={`stat-val ${variant}`}>{value}</div>
    </div>
  )
}
