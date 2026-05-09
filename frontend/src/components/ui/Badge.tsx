import React from 'react'

export interface BadgeProps {
  variant: 'red' | 'green' | 'blue' | 'yellow'
  className?: string
  children: React.ReactNode
}

export function Badge({ variant, className = '', children }: BadgeProps) {
  return (
    <span className={`badge badge-${variant} ${className}`.trim()}>
      {children}
    </span>
  )
}
