import React, { useEffect, useCallback } from 'react'

export interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
  width?: string
}

export function Modal({ open, onClose, title, children, width = '700px' }: ModalProps) {
  const handleOverlayClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.target === e.currentTarget) onClose()
    },
    [onClose]
  )

  useEffect(() => {
    if (!open) return
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleEsc)
    return () => window.removeEventListener('keydown', handleEsc)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className={`modal-overlay ${open ? 'open' : ''}`.trim()} onClick={handleOverlayClick}>
      <div className="modal" style={{ width }}>
        <button className="modal-close" onClick={onClose} aria-label="Close">
          &times;
        </button>
        <div className="modal-title">{title}</div>
        {children}
      </div>
    </div>
  )
}
