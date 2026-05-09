export interface PaginationProps {
  page: number
  totalPages: number
  onPageChange: (page: number) => void
  disabled?: boolean
  totalHint?: string
}

export function Pagination({
  page,
  totalPages,
  onPageChange,
  disabled = false,
  totalHint,
}: PaginationProps) {
  const safeTotal = Math.max(1, totalPages)
  const isFirst = page <= 1
  const isLast = page >= safeTotal

  return (
    <div className="pagination">
      <button
        className="pg-btn"
        disabled={disabled || isFirst}
        onClick={() => onPageChange(1)}
      >
        &laquo; First
      </button>
      <button
        className="pg-btn"
        disabled={disabled || isFirst}
        onClick={() => onPageChange(page - 1)}
      >
        &lsaquo; Prev
      </button>
      <span className="pg-info">
        Page {page} / {safeTotal}
        {totalHint && `, ${totalHint}`}
      </span>
      <button
        className="pg-btn"
        disabled={disabled || isLast}
        onClick={() => onPageChange(page + 1)}
      >
        Next &rsaquo;
      </button>
      <button
        className="pg-btn"
        disabled={disabled || isLast}
        onClick={() => onPageChange(safeTotal)}
      >
        Last &raquo;
      </button>
    </div>
  )
}
