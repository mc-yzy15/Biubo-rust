import { useState, useEffect } from 'react'
import type { WafInfoResponse } from '../types'

export function useDashboardData(host: string | null) {
  const [data, setData] = useState<WafInfoResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!host) return

    const fetchData = async () => {
      setLoading(true)
      setError(null)
      try {
        const url = `/biubo-cgi/info/biubo/waf?host=${encodeURIComponent(host)}`
        const res = await fetch(url)
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`)
        }
        const json = await res.json()
        setData(json)
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : 'Unknown error'
        setError(msg)
        console.error('Dashboard data fetch failed:', e)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [host])

  return { data, loading, error }
}
