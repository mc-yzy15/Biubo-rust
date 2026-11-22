import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Log } from '../types'

const WAF_BASE = '/biubo-cgi'
const LOG_PAGE_SIZE = 10
export type LogTypeFilter = 'all' | 'normal' | 'hacker' | 'challenge'

interface ApiEnvelope<T> {
  status?: string
  data?: T
  message?: string
}

async function readApiData<T>(response: Response): Promise<T> {
  const payload = await response.json() as ApiEnvelope<T> | T
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  if (payload && typeof payload === 'object' && 'status' in payload) {
    const envelope = payload as ApiEnvelope<T>
    if (envelope.status === 'error') throw new Error(envelope.message || 'Request failed')
    return envelope.data as T
  }
  return payload as T
}

function logTimestamp(log: Log): number {
  if (typeof log.timestamp === 'number') return log.timestamp
  if (typeof log.time === 'string') return Date.parse(log.time) || 0
  return 0
}

function logMatchesType(log: Log, filter: LogTypeFilter): boolean {
  if (filter === 'all') return true
  const type = String(log.type || '').toLowerCase()
  const attackTypes = Array.isArray(log.attack_types)
    ? log.attack_types.map(value => String(value).toLowerCase())
    : []
  if (filter === 'hacker') return type === 'hacker' || attackTypes.length > 0
  if (filter === 'challenge') return type === 'challenge' || type === 'challenged'
  return type === 'normal' && attackTypes.length === 0
}

export function useLogs(host: string | null) {
  const [allLogs, setAllLogs] = useState<Log[]>([])
  const [totalRecords, setTotalRecords] = useState(0)
  const [searchLogs, setSearchLogs] = useState<Log[]>([])
  const [searchMode, setSearchMode] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<LogTypeFilter>('all')
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedLog, setSelectedLog] = useState<Log | null>(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [rrwebLoading, setRrwebLoading] = useState(false)
  const [rrwebEvents, setRrwebEvents] = useState<unknown[]>([])
  const [hasReplayData, setHasReplayData] = useState(false)
  const requestIdRef = useRef(0)
  const fetchIdRef = useRef(0)
  const previousHostRef = useRef(host)

  useEffect(() => {
    if (previousHostRef.current !== host) {
      previousHostRef.current = host
      fetchIdRef.current += 1
      setPage(1)
      setSearchMode(false)
      setSearchLogs([])
      setSearchQuery('')
    }
  }, [host])

  const loadLogs = useCallback(async () => {
    const fetchId = ++fetchIdRef.current
    if (!host) {
      setAllLogs([])
      setTotalRecords(0)
      setSearchLogs([])
      setSearchMode(false)
      setError(null)
      return
    }

    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams({
        host,
        limit: String(LOG_PAGE_SIZE),
        offset: String((page - 1) * LOG_PAGE_SIZE),
        type: typeFilter,
      })
      const data = await readApiData<{ logs?: Log[]; total?: number } | Log[]>(
        await fetch(`${WAF_BASE}/info/biubo/log?${params}`),
      )
      const logs = Array.isArray(data) ? data : Array.isArray(data?.logs) ? data.logs : []
      logs.sort((a, b) => logTimestamp(b) - logTimestamp(a))
      if (fetchId !== fetchIdRef.current) return
      setAllLogs(logs)
      setTotalRecords(Array.isArray(data) ? logs.length : Number(data.total ?? logs.length))
    } catch (e: unknown) {
      if (fetchId === fetchIdRef.current) setError(e instanceof Error ? e.message : 'Request failed')
    } finally {
      if (fetchId === fetchIdRef.current) setLoading(false)
    }
  }, [host, page, typeFilter])

  useEffect(() => {
    if (!searchMode) void loadLogs()
  }, [loadLogs, searchMode])

  const filteredSearchLogs = useMemo(
    () => searchLogs.filter(log => logMatchesType(log, typeFilter)),
    [searchLogs, typeFilter],
  )
  const totalPages = Math.max(1, Math.ceil((searchMode ? filteredSearchLogs.length : totalRecords) / LOG_PAGE_SIZE))
  const pageLogs = searchMode
    ? filteredSearchLogs.slice((page - 1) * LOG_PAGE_SIZE, page * LOG_PAGE_SIZE)
    : allLogs

  useEffect(() => {
    if (page > totalPages) setPage(totalPages)
  }, [page, totalPages])

  const handleSearch = useCallback(async () => {
    const statement = searchQuery.trim()
    if (!statement) {
      setSearchMode(false)
      setSearchLogs([])
      setPage(1)
      setError(null)
      return
    }
    if (!host) {
      setError('No host selected')
      return
    }

    const fetchId = ++fetchIdRef.current
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams({ host, statement })
      const data = await readApiData<Log[]>(await fetch(`${WAF_BASE}/info/biubo/search?${params}`))
      const logs = Array.isArray(data) ? data : []
      logs.sort((a, b) => logTimestamp(b) - logTimestamp(a))
      if (fetchId !== fetchIdRef.current) return
      setSearchLogs(logs)
      setSearchMode(true)
      setPage(1)
    } catch (e: unknown) {
      if (fetchId === fetchIdRef.current) setError(e instanceof Error ? e.message : 'Request failed')
    } finally {
      if (fetchId === fetchIdRef.current) setLoading(false)
    }
  }, [host, searchQuery])

  const handleClearSearch = useCallback(() => {
    fetchIdRef.current += 1
    setLoading(false)
    setSearchQuery('')
    setSearchMode(false)
    setSearchLogs([])
    setError(null)
    setPage(1)
  }, [])

  const handleGoPage = useCallback((nextPage: number) => {
    setPage(Math.max(1, Math.min(nextPage, totalPages)))
  }, [totalPages])

  const openDetail = useCallback(async (log: Log) => {
    const requestId = ++requestIdRef.current
    setSelectedLog(log)
    setModalOpen(true)
    setRrwebEvents([])
    setHasReplayData(false)
    setRrwebLoading(Boolean(host && log.request_id))

    if (!host || !log.request_id) return

    try {
      const params = new URLSearchParams({ host, id: log.request_id })
      const events = await readApiData<unknown[]>(await fetch(`${WAF_BASE}/info/biubo/rrweb?${params}`))
      if (requestId !== requestIdRef.current) return
      if (Array.isArray(events) && events.length > 1) {
        setRrwebEvents(events)
        setHasReplayData(true)
      }
    } catch {
      // Keep the log detail available even if replay data cannot be loaded.
    } finally {
      if (requestId === requestIdRef.current) setRrwebLoading(false)
    }
  }, [host])

  const closeDetail = useCallback(() => {
    requestIdRef.current += 1
    setModalOpen(false)
    setSelectedLog(null)
    setRrwebEvents([])
    setHasReplayData(false)
    setRrwebLoading(false)
  }, [])

  const handleTypeFilter = useCallback((filter: LogTypeFilter) => {
    setTypeFilter(filter)
    setPage(1)
  }, [])

  return {
    allLogs,
    searchMode,
    searchQuery,
    typeFilter,
    page,
    totalPages,
    pageLogs,
    filteredCount: searchMode ? filteredSearchLogs.length : totalRecords,
    loading,
    error,
    selectedLog,
    modalOpen,
    rrwebLoading,
    rrwebEvents,
    hasReplayData,
    setSearchQuery,
    handleSearch,
    handleClearSearch,
    handleTypeFilter,
    handleGoPage,
    loadLogs,
    openDetail,
    closeDetail,
  }
}
