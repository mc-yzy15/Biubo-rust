import { useState, useCallback, useRef, useEffect } from 'react'
import { Log, UseLogsReturn } from '../types'

const WAF_BASE = '/biubo-cgi'
const LOG_PAGE_SIZE = 10

function todayStr(): string {
  const d = new Date()
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

function dateOffset(dateStr: string, days: number): string {
  const d = new Date(dateStr + 'T00:00:00')
  d.setDate(d.getDate() + days)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

async function fetchDayLogs(date: string): Promise<Log[]> {
  try {
    const r = await fetch(`${WAF_BASE}/info/biubo/log?date=${encodeURIComponent(date)}`)
    if (!r.ok) return []
    const data = await r.json()
    const logs: Log[] = Array.isArray(data) ? data : []
    logs.forEach(l => { if (!l._date) l._date = date })
    return logs
  } catch {
    return []
  }
}

export function useLogs(host: string | null): UseLogsReturn {
  const [allLogs, setAllLogs] = useState<Log[]>([])
  const [searchLogs, setSearchLogs] = useState<Log[]>([])
  const [searchMode, setSearchMode] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [loading, setLoading] = useState(false)
  const [noMoreData, setNoMoreData] = useState(false)
  const [loadedDates, setLoadedDates] = useState<string[]>([])
  const [currentDate, setCurrentDate] = useState(todayStr())
  const [modalOpen, setModalOpen] = useState(false)
  const [selectedLog, setSelectedLog] = useState<Log | null>(null)
  const [rrwebLoading, setRrwebLoading] = useState(false)
  const [rrwebEvents, setRrwebEvents] = useState<unknown[]>([])
  const [hasReplayData, setHasReplayData] = useState(false)
  const rrwebPlayerRef = useRef<InstanceType<typeof window.rrwebPlayer> | null>(null)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => { mountedRef.current = false }
  }, [])

  const loadMoreLogs = useCallback(async () => {
    if (loading || noMoreData) return

    setLoading(true)

    let cur: string
    if (loadedDates.length > 0) {
      cur = dateOffset(loadedDates[loadedDates.length - 1], -1)
    } else {
      cur = todayStr()
    }

    for (let tried = 0; tried < 60; tried++) {
      if (loadedDates.includes(cur)) {
        cur = dateOffset(cur, -1)
        continue
      }

      setLoadedDates(prev => [...prev, cur])
      const logs = await fetchDayLogs(cur)

      if (logs.length > 0) {
        logs.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
        setAllLogs(prev => [...prev, ...logs])
        if (mountedRef.current) {
          setLoading(false)
          setCurrentDate(cur)
        }
        return
      }

      const daysDiff = Math.round((new Date(todayStr()).getTime() - new Date(cur + 'T00:00:00').getTime()) / 86400000)
      if (daysDiff > 365) {
        if (mountedRef.current) {
          setNoMoreData(true)
          setLoading(false)
        }
        break
      }
      cur = dateOffset(cur, -1)
    }

    if (mountedRef.current) {
      setLoading(false)
      if (allLogs.length === 0) {
        setNoMoreData(true)
      }
    }
  }, [loading, noMoreData, loadedDates, allLogs.length])

  const initLogs = useCallback(async () => {
    setAllLogs([])
    setLoadedDates([])
    setNoMoreData(false)
    setLoading(false)
    setSearchMode(false)
    setSearchLogs([])
    setPage(1)
    setCurrentDate(todayStr())

    let cur = todayStr()

    for (let tried = 0; tried < 60; tried++) {
      const logs = await fetchDayLogs(cur)

      if (logs.length > 0) {
        logs.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
        if (mountedRef.current) {
          setAllLogs(logs)
          setLoadedDates([cur])
          setCurrentDate(cur)
          setLoading(false)
        }
        return
      }

      const daysDiff = Math.round((new Date(todayStr()).getTime() - new Date(cur + 'T00:00:00').getTime()) / 86400000)
      if (daysDiff > 365) {
        if (mountedRef.current) {
          setNoMoreData(true)
          setLoading(false)
        }
        break
      }
      cur = dateOffset(cur, -1)
    }

    if (mountedRef.current) {
      setLoading(false)
      setNoMoreData(true)
    }
  }, [])

  useEffect(() => {
    if (!host) return
    initLogs()
  }, [host, initLogs])

  useEffect(() => {
    const logs = searchMode ? searchLogs : allLogs
    const tp = Math.max(1, Math.ceil(logs.length / LOG_PAGE_SIZE))
    setTotalPages(tp)
    if (page > tp) setPage(tp > 0 ? tp : 1)
  }, [allLogs, searchLogs, searchMode, page])

  const handleSearch = useCallback(async () => {
    const stmt = searchQuery.trim()
    if (!stmt) {
      handleClearSearch()
      return
    }
    setLoading(true)
    try {
      const r = await fetch(`${WAF_BASE}/info/biubo/search?statement=${encodeURIComponent(stmt)}`)
      const data = await r.json()
      if (data.error) {
        if (mountedRef.current) {
          setLoading(false)
        }
        return
      }
      const logs: Log[] = Array.isArray(data) ? data : []
      logs.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
      if (mountedRef.current) {
        setSearchMode(true)
        setSearchLogs(logs)
        setPage(1)
        setLoading(false)
      }
    } catch {
      if (mountedRef.current) {
        setLoading(false)
      }
    }
  }, [searchQuery])

  const handleClearSearch = useCallback(() => {
    setSearchQuery('')
    setSearchMode(false)
    setSearchLogs([])
    setPage(1)
  }, [])

  const handlePrevDay = useCallback(() => {
    if (loadedDates.length === 0) return
    const idx = loadedDates.length - 1
    const prev = dateOffset(loadedDates[idx], -1)
    setLoadedDates(dates => [...dates, prev])
    setCurrentDate(prev)
    fetchDayLogs(prev).then(logs => {
      if (logs.length > 0) {
        logs.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
        setAllLogs(prev => [...prev, ...logs])
      }
    })
  }, [loadedDates])

  const handleNextDay = useCallback(() => {
    if (loadedDates.length <= 1) return
    const idx = loadedDates.length - 2
    setCurrentDate(loadedDates[idx])
  }, [loadedDates])

  const handleGoPage = useCallback((p: number) => {
    if (searchMode) {
      if (p < 1 || p > totalPages) return
      setPage(p)
      return
    }

    const logs = allLogs
    const tp = Math.max(1, Math.ceil(logs.length / LOG_PAGE_SIZE))

    if (p >= tp && !noMoreData) {
      setLoading(true)
      loadMoreLogs().then(() => {
        if (mountedRef.current) {
          const newTotal = Math.max(1, Math.ceil(allLogs.length / LOG_PAGE_SIZE))
          setPage(Math.min(p, newTotal))
          setLoading(false)
        }
      })
      return
    }

    if (p < 1) p = 1
    if (p > tp) p = tp
    setPage(p)
  }, [searchMode, totalPages, allLogs, noMoreData, loadMoreLogs])

  const openDetail = useCallback((log: Log) => {
    setSelectedLog(log)
    setModalOpen(true)
    setRrwebEvents([])
    setHasReplayData(false)
    setRrwebLoading(true)

    if (rrwebPlayerRef.current) {
      try {
        rrwebPlayerRef.current.$destroy?.()
      } catch { }
      rrwebPlayerRef.current = null
    }

    const rid = log.request_id
    const d = log._date
    if (!rid || !d) {
      setRrwebLoading(false)
      return
    }

    fetch(`${WAF_BASE}/info/biubo/rrweb?date=${encodeURIComponent(d)}&id=${encodeURIComponent(rid)}`)
      .then(r => r.json())
      .then(events => {
        if (!mountedRef.current) return
        if (!Array.isArray(events) || events.length < 2) {
          setRrwebLoading(false)
          return
        }
        setRrwebEvents(events)
        setHasReplayData(true)
        setRrwebLoading(false)

        setTimeout(() => {
          const playerEl = document.getElementById('modal-replay-player')
          if (playerEl && window.rrwebPlayer) {
            try {
              rrwebPlayerRef.current = new window.rrwebPlayer({
                target: playerEl,
                props: {
                  events,
                  autoPlay: false,
                  width: playerEl.offsetWidth || 760,
                  height: 400,
                },
              })
            } catch { }
          }
        }, 100)
      })
      .catch(() => {
        if (mountedRef.current) {
          setRrwebLoading(false)
        }
      })
  }, [])

  const closeDetail = useCallback(() => {
    setModalOpen(false)
    setSelectedLog(null)
    setRrwebEvents([])
    setHasReplayData(false)
    if (rrwebPlayerRef.current) {
      try {
        rrwebPlayerRef.current.$destroy?.()
      } catch { }
      rrwebPlayerRef.current = null
    }
  }, [])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeDetail()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [closeDetail])

  return {
    allLogs,
    searchLogs,
    searchMode,
    searchQuery,
    page,
    totalPages,
    loading,
    noMoreData,
    loadedDates,
    currentDate,
    selectedLog,
    modalOpen,
    rrwebLoading,
    rrwebEvents,
    hasReplayData,
    setSearchQuery,
    handleSearch,
    handleClearSearch,
    handlePrevDay,
    handleNextDay,
    handleGoPage,
    openDetail,
    closeDetail,
  }
}
