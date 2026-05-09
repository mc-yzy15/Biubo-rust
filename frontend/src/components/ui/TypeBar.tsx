export interface TypeBarItem {
  label: string
  value: number
  color: string
}

export interface TypeBarProps {
  items: TypeBarItem[]
  maxItems?: number
}

export function TypeBar({ items, maxItems = 8 }: TypeBarProps) {
  const sorted = [...items].sort((a, b) => b.value - a.value).slice(0, maxItems)
  const max = sorted[0]?.value || 1

  if (sorted.length === 0) return null

  return (
    <>
      {sorted.map((item, idx) => (
        <div key={idx} className="type-bar-row">
          <div className="type-label">{item.label}</div>
          <div className="type-bar-bg">
            <div className="type-bar-fill" style={{ width: `${(item.value / max) * 100}%`, background: item.color }} />
          </div>
          <div className="type-count">{item.value}</div>
        </div>
      ))}
    </>
  )
}
