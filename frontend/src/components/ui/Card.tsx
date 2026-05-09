import React from 'react'

export interface CardProps {
  title?: string
  titleIcon?: React.ReactNode
  className?: string
  children: React.ReactNode
}

export function Card({ title, titleIcon, className = '', children }: CardProps) {
  return (
    <div className={`card ${className}`.trim()}>
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
