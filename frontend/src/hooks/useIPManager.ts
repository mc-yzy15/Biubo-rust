import { useState, useCallback, useEffect, useRef } from 'react'

const WAF_BASE = '/biubo-cgi'

async function wafRequest<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${WAF_BASE}${url}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

const wafApi = {
  get: <T>(url: string) => wafRequest<T>(url, { method: 'GET' }),
  post: <T>(url: string, body: unknown) =>
    wafRequest<T>(url, { method: 'POST', body: JSON.stringify(body) }),
}

export interface BlacklistEntry {
  ip: string
  reason: string
  banned_at?: string
}

export interface WhitelistEntry {
  ip: string
  note: string
}

interface RawBlacklistData {
  [ip: string]: { reason?: string; banned_at?: string } | string
}

interface RawWhitelistData {
  [ip: string]: { note?: string } | string
}

interface ApiResponse {
  status?: string
  msg?: string
}

function parseBlacklist(data: RawBlacklistData): BlacklistEntry[] {
  return Object.entries(data).map(([ip, info]) => ({
    ip,
    reason: typeof info === 'object' ? (info.reason || '-') : info,
    banned_at: typeof info === 'object' ? info.banned_at : undefined,
  }))
}

function parseWhitelist(data: RawWhitelistData): WhitelistEntry[] {
  return Object.entries(data).map(([ip, info]) => ({
    ip,
    note: typeof info === 'object' ? (info.note || '-') : (info || '-'),
  }))
}

export function useIPManager(host: string | null) {
  const [blacklist, setBlacklist] = useState<BlacklistEntry[]>([])
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => { mountedRef.current = false }
  }, [])

  const loadBlacklist = useCallback(async () => {
    if (!host) return
    try {
      const data = await wafApi.get<RawBlacklistData>(
        `/info/biubo/blacklist?host=${encodeURIComponent(host)}`
      )
      if (mountedRef.current) {
        setBlacklist(parseBlacklist(data))
      }
    } catch (e) {
      console.error('Failed to load blacklist:', e)
    }
  }, [host])

  const loadWhitelist = useCallback(async () => {
    if (!host) return
    try {
      const data = await wafApi.get<RawWhitelistData>(
        `/info/biubo/whitelist?host=${encodeURIComponent(host)}`
      )
      if (mountedRef.current) {
        setWhitelist(parseWhitelist(data))
      }
    } catch (e) {
      console.error('Failed to load whitelist:', e)
    }
  }, [host])

  const loadAll = useCallback(async () => {
    if (!host) return
    setLoading(true)
    setError(null)
    try {
      await Promise.all([loadBlacklist(), loadWhitelist()])
    } catch (e) {
      if (mountedRef.current) {
        setError(e instanceof Error ? e.message : 'Unknown error')
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false)
      }
    }
  }, [host, loadBlacklist, loadWhitelist])

  const banIP = useCallback(async (ip: string, reason: string): Promise<boolean> => {
    if (!host) return false
    try {
      const res = await wafApi.post<ApiResponse>(
        `/info/biubo/ban?host=${encodeURIComponent(host)}`,
        { ip, reason }
      )
      if (res.status === 'success') {
        await loadBlacklist()
        return true
      }
      return false
    } catch (e) {
      console.error('Failed to ban IP:', e)
      return false
    }
  }, [host, loadBlacklist])

  const unbanIP = useCallback(async (ip: string): Promise<boolean> => {
    if (!host) return false
    try {
      const res = await wafApi.get<ApiResponse>(
        `/info/biubo/unban?ip=${encodeURIComponent(ip)}&host=${encodeURIComponent(host)}`
      )
      if (res.status === 'success') {
        await loadBlacklist()
        return true
      }
      return false
    } catch (e) {
      console.error('Failed to unban IP:', e)
      return false
    }
  }, [host, loadBlacklist])

  const addWhitelistIP = useCallback(async (ip: string, note: string): Promise<boolean> => {
    if (!host) return false
    try {
      const res = await wafApi.post<ApiResponse>(
        '/info/biubo/add_whitelist',
        { ip, note, host }
      )
      if (res.status === 'success') {
        await loadWhitelist()
        return true
      }
      return false
    } catch (e) {
      console.error('Failed to add whitelist:', e)
      return false
    }
  }, [host, loadWhitelist])

  const removeWhitelistIP = useCallback(async (ip: string): Promise<boolean> => {
    if (!host) return false
    try {
      const res = await wafApi.get<ApiResponse>(
        `/info/biubo/remove_whitelist?ip=${encodeURIComponent(ip)}&host=${encodeURIComponent(host)}`
      )
      if (res.status === 'success') {
        await loadWhitelist()
        return true
      }
      return false
    } catch (e) {
      console.error('Failed to remove whitelist:', e)
      return false
    }
  }, [host, loadWhitelist])

  useEffect(() => {
    if (host) {
      loadAll()
    }
  }, [host, loadAll])

  return {
    blacklist,
    whitelist,
    loading,
    error,
    loadBlacklist,
    loadWhitelist,
    banIP,
    unbanIP,
    addWhitelistIP,
    removeWhitelistIP,
  }
}
