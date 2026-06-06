import { useMemo } from 'react'
import { useDashboardData } from './useDashboardData'

export interface ProcessedDashboardData {
  totalRequests: number
  blockedAttacks: number
  uniqueVisitors: number
  blockRate: string
  engagement: {
    totalSessions: number
    bounceRate: string
    avgSessionDuration: string
  }
  sources: { label: string; value: number; color: string }[]
  attackTypes: { label: string; value: number; color: string }[]
  devices: { label: string; value: number; color: string }[]
  browsers: { label: string; value: number; color: string }[]
  osList: { label: string; value: number; color: string }[]
  topIPs: [string, string | number][]
  topURLs: [string, string | number][]
  trendingURLs: { label: string; value: number; color: string }[]
  attackerGeo: { label: string; value: number; color: string }[]
  visitorGeo: { label: string; value: number; color: string }[]
  siteInfo: {
    domain: string
    status: string
    statusColor: string
    description: string
    createdAt: string
  }
}

export function useDashboard(host: string | null): {
  data: ProcessedDashboardData | null
  loading: boolean
  error: string | null
} {
  const { data: raw, loading, error } = useDashboardData(host)

  const processed = useMemo((): ProcessedDashboardData | null => {
    if (!raw) return null

    const traffic = raw.analytics?.traffic || {}
    const sec = raw.analytics?.security || {}
    const clients = raw.analytics?.clients || {}
    const site = raw.site || {}
    const trending = raw.analytics?.trending_urls || {}

    const totalRequests = traffic.visitors?.total || 0
    const blockedAttacks = sec.blocked_requests || 0
    const uniqueVisitors = traffic.visitors?.unique?.length || 0
    const blockRate = sec.block_rate ? `${(sec.block_rate * 100).toFixed(1)}%` : '0%'

    const eng = traffic.engagement || {}
    const avgDur = eng.avg_session_duration ? `${eng.avg_session_duration.toFixed(1)}s` : '-'
    const bounce = eng.bounce_rate ? `${(eng.bounce_rate * 100).toFixed(1)}%` : '-'

    const src = traffic.sources || {}
    const sources = [
      { label: 'direct', value: src.direct || 0, color: 'var(--accent)' },
      { label: 'searchEngine', value: src.search || 0, color: 'var(--green)' },
      { label: 'socialMedia', value: src.social || 0, color: 'var(--yellow)' },
      { label: 'referral', value: src.referral || 0, color: '#ff7700' },
    ]

    const at = sec.attack_types || {}
    const attackTypes = Object.entries(at)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([k, v]) => ({ label: k, value: v, color: 'var(--red)' }))

    const dev = clients.devices || {}
    const br = clients.browsers || {}
    const os = clients.os || {}
    const devices = Object.entries(dev)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([k, v]) => ({ label: k, value: v, color: 'var(--accent)' }))
    const browsers = Object.entries(br)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([k, v]) => ({ label: k, value: v, color: 'var(--green)' }))
    const osList = Object.entries(os)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([k, v]) => ({ label: k, value: v, color: 'var(--yellow)' }))

    const ips = sec.top_attack_ips || {}
    const ipArr: [string, string | number][] = typeof ips === 'object' && !Array.isArray(ips)
      ? Object.entries(ips).sort((a, b) => b[1] - a[1]).slice(0, 8)
      : Array.isArray(ips)
        ? ips.slice(0, 8).map(([ip, cnt]) => [ip, cnt ?? '-'])
        : []

    const urls = sec.top_target_urls || {}
    const urlArr: [string, string | number][] = typeof urls === 'object' && !Array.isArray(urls)
      ? Object.entries(urls).sort((a, b) => b[1] - a[1]).slice(0, 8)
      : Array.isArray(urls)
        ? urls.slice(0, 8).map(([u, cnt]) => [u, cnt ?? '-'])
        : []

    const trendArr = typeof trending === 'object' && !Array.isArray(trending)
      ? Object.entries(trending).sort((a, b) => b[1] - a[1]).slice(0, 8)
      : []
    const trendingURLs = trendArr.map(([url, cnt]) => ({ label: url, value: cnt, color: 'var(--accent2)' }))

    const geo = sec.geo?.attackers_by_country || {}
    const attackerGeo = Object.entries(geo)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([c, n]) => ({ label: c, value: n, color: 'var(--red)' }))

    const vgeo = sec.geo?.visitors_by_country || {}
    const visitorGeo = Object.entries(vgeo)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([c, n]) => ({ label: c, value: n, color: 'var(--accent)' }))

    const statusColor = site.status === 'on' ? 'var(--green)' : site.status === 'off' ? 'var(--red)' : 'var(--yellow)'

    return {
      totalRequests,
      blockedAttacks,
      uniqueVisitors,
      blockRate,
      engagement: {
        totalSessions: eng.total || 0,
        bounceRate: bounce,
        avgSessionDuration: avgDur,
      },
      sources,
      attackTypes,
      devices,
      browsers,
      osList,
      topIPs: ipArr,
      topURLs: urlArr,
      trendingURLs,
      attackerGeo,
      visitorGeo,
      siteInfo: {
        domain: site.domain || '-',
        status: site.status || '-',
        statusColor,
        description: site.description || '-',
        createdAt: site.created_at || '-',
      },
    }
  }, [raw])

  return { data: processed, loading, error }
}
