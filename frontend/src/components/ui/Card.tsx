import React from 'react'

export interface CardProps {
  title?: string
  titleIcon?: React.ReactNode
  className?: string
  style?: React.CSSProperties
  children: React.ReactNode
}

export function Card({ title, titleIcon, className = '', style, children }: CardProps) {
  return (
    <div className={`card ${className}`.trim()} style={style}>
      {title && (
        <div className="card-title">
          {titleIcon}
          {title}
        </div>
      )}
      {children}
    </div>
  )
}
