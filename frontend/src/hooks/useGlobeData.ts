import { useState, useEffect, useRef, useCallback } from 'react'
import type { Log } from '../types'

export interface GeoCoords {
  lat: number
  lng: number
  flag: string
}

export interface AttackNode {
  country: string
  city: string
  lat: number
  lng: number
  flag: string
}

export interface AttackData {
  id: string
  attacker: AttackNode
  server: AttackNode
  type: string
  sev: number
  timestamp: number
  addedAt: number
  _sc: string
  _dc: string
  _ttl: number
  _real: boolean
}

const TYPE_COLOR_MAP: Record<string, string> = {
  'hacker': '#ff3a3a', 'sql': '#ff7700', 'xss': '#ffd700', 'ddos': '#ff3aff',
  'bot': '#aa00ff', 'scan': '#00c8ff', 'brute': '#00ff8c', 'upload': '#ff5588',
  'rce': '#ff3a3a', 'lfi': '#ff7700', 'normal': '#00c8ff',
}

const SEEN_IDS_MAX = 2000

function getFlagEmoji(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return '\ud83c\udf10'
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0))
  return String.fromCodePoint(...codePoints)
}

function safeStr(val: unknown): string {
  if (val == null) return ''
  return String(val)
}

function safeNum(val: unknown, fallback = 0): number {
  if (val == null) return fallback
  const n = Number(val)
  return isNaN(n) ? fallback : n
}

export function useGlobeData(_host: string | null) {
  const [attackData, setAttackData] = useState<AttackData[]>([])
  const [serverNode, setServerNode] = useState<AttackNode>({
    country: 'Unknown',
    city: 'Resolving...',
    lat: 0,
    lng: 0,
    flag: '\ud83c\udf10',
  })
  const [stats, setStats] = useState({
    total: 0,
    blocked: 0,
    critical: 0,
    ratePerMin: 0,
  })
  const [typeCounts, setTypeCounts] = useState<Record<string, number>>({})
  const [countryCounts, setCountryCounts] = useState<Record<string, number>>({})
  const [ipSearchResults, setIpSearchResults] = useState<Log[]>([])
  const [ipSearchLoading, setIpSearchLoading] = useState(false)
  const [autoRotate, setAutoRotate] = useState(true)
  const [paused, setPaused] = useState(false)
  const [speed, setSpeed] = useState(4)

  const seenIdsRef = useRef<Set<string>>(new Set())
  const geoCacheRef = useRef<Map<string, GeoCoords>>(new Map())
  const rateWindowRef = useRef<number[]>([])
  const globeRef = useRef<any>(null)

  const fetchServerLocation = useCallback(async () => {
    try {
      const r = await fetch('/biubo-cgi/info/biubo/location')
      const d = await r.json()
      if (d.status === 'success' && d.data.lat != null) {
        setServerNode({
          country: d.data.country || 'Unknown',
          city: d.data.city || '',
          lat: safeNum(d.data.lat),
          lng: safeNum(d.data.lon),
          flag: getFlagEmoji(safeStr(d.data.country_code)),
        })
      }
    } catch (e) {
      console.warn('Failed to resolve server location:', e)
    }
  }, [])

  const getGeo = useCallback(async (log: Log): Promise<GeoCoords> => {
    const countryCode = safeStr(log.country_code)
    const country = safeStr(log.country)
    const city = safeStr(log.city)

    if (log.lat != null && (log as any).lon != null) {
      return { lat: safeNum(log.lat), lng: safeNum((log as any).lon), flag: getFlagEmoji(countryCode) }
    }

    const cacheKey = `${country}_${city}`
    if (geoCacheRef.current.has(cacheKey)) {
      return { ...geoCacheRef.current.get(cacheKey)!, flag: getFlagEmoji(countryCode) }
    }

    if (city || country) {
      try {
        const resp = await fetch(`/biubo-cgi/api/biubo/geocode?city=${encodeURIComponent(city)}&country=${encodeURIComponent(country)}`)
        const res = await resp.json()
        if (res.status === 'success' && res.data.lat) {
          const coords: GeoCoords = { lat: safeNum(res.data.lat), lng: safeNum(res.data.lon), flag: getFlagEmoji(countryCode) }
          geoCacheRef.current.set(cacheKey, coords)
          return coords
        }
      } catch (e) {
        console.warn('Geocoding fallback error:', e)
      }
    }

    return { lat: (Math.random() * 140) - 70, lng: (Math.random() * 360) - 180, flag: getFlagEmoji(countryCode) }
  }, [])

  const logToAttack = useCallback(async (log: Log, server: AttackNode): Promise<AttackData> => {
    const geo = await getGeo(log)
    const rawType = (log.attack_types && log.attack_types[0]) || log.type || 'normal'
    const type = safeStr(rawType)
    const typeKey = type.toLowerCase().replace(/[^a-z]/g, '')
    const color = TYPE_COLOR_MAP[typeKey] || '#ff3a3a'
    const isBlocked = safeNum(log.status) >= 400 || log.type === 'hacker'
    const sev = isBlocked ? (log.attack_types && log.attack_types.length > 1 ? 3 : 2) : 1
    const ts = log.timestamp ? log.timestamp * 1000 : (log.time ? new Date(log.time).getTime() : Date.now())
    return {
      id: log.request_id || Math.random().toString(36).slice(2),
      attacker: { country: safeStr(log.country) || 'Unknown', city: safeStr(log.city), lat: geo.lat, lng: geo.lng, flag: geo.flag },
      server: { ...server },
      type, sev,
      timestamp: ts,
      addedAt: Date.now(),
      _sc: color, _dc: '#00c8ff',
      _ttl: 120000 + sev * 10000,
      _real: true,
    }
  }, [getGeo])

  const markSeen = useCallback((id: string) => {
    const seen = seenIdsRef.current
    if (seen.size >= SEEN_IDS_MAX) {
      const iter = seen.values()
      for (let i = 0; i < 200; i++) {
        const result = iter.next()
        if (result.done) break
        seen.delete(result.value)
      }
    }
    seen.add(id)
  }, [])

  const pushAttack = useCallback((attack: AttackData) => {
    setStats(prev => {
      const newTotal = prev.total + 1
      const newCritical = prev.critical + (attack.sev === 3 ? 1 : 0)
      const newBlocked = prev.blocked + (attack.sev >= 2 ? 1 : 0)
      return { total: newTotal, blocked: newBlocked, critical: newCritical, ratePerMin: 0 }
    })
    rateWindowRef.current.push(Date.now())

    setTypeCounts(prev => {
      const next = { ...prev }
      next[attack.type] = (next[attack.type] || 0) + 1
      return next
    })

    setCountryCounts(prev => {
      const next = { ...prev }
      next[attack.attacker.country] = (next[attack.attacker.country] || 0) + 1
      return next
    })

    setAttackData(prev => {
      const now = Date.now()
      const filtered = prev.filter(d => (now - (d.addedAt || d.timestamp)) < d._ttl)
      const next = [...filtered, attack]
      if (next.length > 2000) next.shift()
      return next
    })
  }, [])

  const fetchData = useCallback(async (dateFrom: string, dateTo: string) => {
    if (paused) return

    const fmt = (d: Date) => `${d.getFullYear()}.${d.getMonth() + 1}.${d.getDate()}`
    const fromDate = new Date(dateFrom + 'T00:00:00')
    const toDate = new Date(dateTo + 'T00:00:00')
    const stmt = `type:hacker AND time:${fmt(fromDate)},${fmt(toDate)}`

    try {
      const r = await fetch(`/biubo-cgi/info/biubo/search?statement=${encodeURIComponent(stmt)}`)
      if (!r.ok) return
      const logs: Log[] = await r.json()
      if (!Array.isArray(logs)) return

      for (const log of logs) {
        const id = log.request_id
        if (id && seenIdsRef.current.has(id)) continue
        if (id) markSeen(id)

        const server = { ...serverNode }
        const attack = await logToAttack(log, server)
        pushAttack(attack)
      }
    } catch (e) {
      console.error('Globe fetch error:', e)
    }
  }, [paused, serverNode, logToAttack, pushAttack, markSeen])

  const searchIP = useCallback(async (ip: string, dateFrom: string, dateTo: string) => {
    if (!ip) return
    setIpSearchLoading(true)

    let stmt = `ip:${ip}`
    if (dateFrom && dateTo) {
      const fromTs = Math.floor(new Date(dateFrom + 'T00:00:00').getTime() / 1000)
      const toTs = Math.floor(new Date(dateTo + 'T23:59:59').getTime() / 1000)
      stmt = `ip:${ip} AND timestamp>=${fromTs} AND timestamp<=${toTs}`
    }

    try {
      const r = await fetch(`/biubo-cgi/info/biubo/search?statement=${encodeURIComponent(stmt)}`)
      const data: Log[] = await r.json()
      setIpSearchResults(Array.isArray(data) ? data.slice(0, 20) : [])
    } catch (e) {
      console.error('IP search error:', e)
      setIpSearchResults([])
    } finally {
      setIpSearchLoading(false)
    }
  }, [])

  const clearAll = useCallback(() => {
    setAttackData([])
    setTypeCounts({})
    setCountryCounts({})
    setStats({ total: 0, blocked: 0, critical: 0, ratePerMin: 0 })
    rateWindowRef.current = []
    if (globeRef.current) {
      globeRef.current.arcsData([]).pointsData([]).ringsData([])
    }
  }, [])

  useEffect(() => {
    fetchServerLocation()
  }, [fetchServerLocation])

  useEffect(() => {
    const interval = setInterval(() => {
      const cutoff = Date.now() - 60000
      rateWindowRef.current = rateWindowRef.current.filter(t => t > cutoff)
      setStats(prev => ({ ...prev, ratePerMin: rateWindowRef.current.length }))
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const today = new Date()
    const todayStr = today.toISOString().slice(0, 10)
    const fromD = new Date(today)
    fromD.setDate(fromD.getDate() - 29)
    const fromStr = fromD.toISOString().slice(0, 10)

    fetchData(fromStr, todayStr)

    const interval = setInterval(() => {
      fetchData(fromStr, todayStr)
    }, Math.max(5000, 15000 / speed))

    return () => clearInterval(interval)
  }, [fetchData, speed])

  return {
    attackData,
    serverNode,
    stats,
    typeCounts,
    countryCounts,
    ipSearchResults,
    ipSearchLoading,
    autoRotate,
    paused,
    speed,
    setAutoRotate,
    setPaused,
    setSpeed,
    clearAll,
    searchIP,
    globeRef,
    pushAttack,
    getGeo,
    logToAttack,
    serverNodeRef: serverNode,
  }
}
