import { useState, useEffect, useRef, useCallback } from 'react'

export interface SystemMetrics {
  cpu: {
    percent: number
    cores: number
  }
  memory: {
    percent: number
    used_gb: number
    total_gb: number
  }
  disk: {
    percent: number
    used_gb: number
    total_gb: number
  }
  os: string
  python_version: string
  uptime: string
  time: string
}

export interface WafStatusInfo {
  site: {
    status: string
    domain: string
    description: string
    created_at: string
  }
}

export interface SystemStatusData {
  metrics: SystemMetrics | null
  wafStatus: WafStatusInfo | null
  loading: boolean
  error: string | null
  refetch: () => Promise<void>
}

export function useSystemStatus(host: string | null): SystemStatusData {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null)
  const [wafStatus, setWafStatus] = useState<WafStatusInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const mountedRef = useRef(true)

  const fetchMetrics = useCallback(async () => {
    if (!host) return
    try {
      const res = await fetch('/biubo-cgi/info/biubo/system')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      if (json.status === 'success' && mountedRef.current) {
        setMetrics(json.data)
        setError(null)
      }
    } catch (e: unknown) {
      if (mountedRef.current) {
        const msg = e instanceof Error ? e.message : 'Unknown error'
        setError(msg)
      }
    }
  }, [host])

  const fetchWafStatus = useCallback(async () => {
    if (!host) return
    try {
      const res = await fetch(`/biubo-cgi/info/biubo/waf?host=${encodeURIComponent(host)}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      if (mountedRef.current) {
        setWafStatus(json)
      }
    } catch (e) {
      // WAF status fetch failure is non-critical
    }
  }, [host])

  const fetchAll = useCallback(async () => {
    if (!host) {
      setLoading(false)
      return
    }
    setLoading(true)
    await Promise.all([fetchMetrics(), fetchWafStatus()])
    if (mountedRef.current) {
      setLoading(false)
    }
  }, [host, fetchMetrics, fetchWafStatus])

  useEffect(() => {
    mountedRef.current = true
    fetchAll()

    const intervalId = setInterval(() => {
      fetchMetrics()
    }, 3000)

    return () => {
      mountedRef.current = false
      clearInterval(intervalId)
    }
  }, [host, fetchAll, fetchMetrics])

  return { metrics, wafStatus, loading, error, refetch: fetchAll }
}
