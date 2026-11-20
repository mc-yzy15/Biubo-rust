import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useApp } from '../../context/AppContext'
import { useLogs, type LogTypeFilter } from '../../hooks/useLogs'
import type { Log } from '../../types'
import { Badge, Card, Modal, Pagination } from '../ui'

const FILTERS: LogTypeFilter[] = ['all', 'hacker', 'challenge', 'normal']

function formatTimestamp(log: Log): string {
  const value = typeof log.timestamp === 'number'
    ? new Date(log.timestamp < 10_000_000_000 ? log.timestamp * 1000 : log.timestamp)
    : new Date(String(log.time || ''))
  return Number.isNaN(value.getTime()) ? String(log.time || '—') : value.toLocaleString()
}

function getLogType(log: Log): 'hacker' | 'challenge' | 'normal' {
  const type = String(log.type || '').toLowerCase()
  if (type === 'hacker' || (Array.isArray(log.attack_types) && log.attack_types.length > 0)) return 'hacker'
  if (type === 'challenge' || type === 'challenged') return 'challenge'
  return 'normal'
}

function getBadgeVariant(type: ReturnType<typeof getLogType>): 'red' | 'yellow' | 'green' {
  if (type === 'hacker') return 'red'
  if (type === 'challenge') return 'yellow'
  return 'green'
}

function printable(value: unknown): string {
  if (value == null || value === '') return '—'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

export function LogsTab() {
  const { t } = useTranslation()
  const { currentHost } = useApp()
  const logs = useLogs(currentHost)
  const playerRef = useRef<HTMLDivElement>(null)
  const playerInstanceRef = useRef<{ $destroy?: () => void } | null>(null)

  useEffect(() => {
    if (!logs.hasReplayData || !playerRef.current || !window.rrwebPlayer) return
    try {
      playerInstanceRef.current = new window.rrwebPlayer({
        target: playerRef.current,
        props: {
          events: logs.rrwebEvents,
          autoPlay: false,
          width: playerRef.current.offsetWidth || 760,
          height: 400,
        },
      })
    } catch {
      playerInstanceRef.current = null
    }
    return () => {
      playerInstanceRef.current?.$destroy?.()
      playerInstanceRef.current = null
    }
  }, [logs.hasReplayData, logs.rrwebEvents])

  const filterLabel: Record<LogTypeFilter, string> = {
    all: t('logs.filterAll'),
    hacker: t('logs.filterAttacks'),
    challenge: t('logs.filterChallenge'),
    normal: t('logs.filterNormal'),
  }

  return (
    <div className="tab-panel" id="tab-logs">
      <Card style={{ marginBottom: 16 }}>
        <form
          onSubmit={(event) => {
            event.preventDefault()
            void logs.handleSearch()
          }}
          style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}
        >
          <input
            value={logs.searchQuery}
            onChange={event => logs.setSearchQuery(event.target.value)}
            placeholder={t('logs.searchPlaceholder')}
            aria-label={t('logs.searchPlaceholder')}
            style={{
              flex: '1 1 260px', minWidth: 0, background: 'rgba(0,100,180,0.1)',
              border: '1px solid var(--border)', borderRadius: 5, padding: '9px 12px',
              color: 'var(--text)', fontFamily: "'Share Tech Mono', monospace", outline: 'none',
            }}
          />
          <button className="tb-btn" type="submit" disabled={logs.loading}>
            {logs.loading ? t('logs.searching') : t('logs.search')}
          </button>
          <button className="tb-btn" type="button" onClick={logs.handleClearSearch}>
            {t('logs.clear')}
          </button>
          <button className="tb-btn" type="button" onClick={() => void logs.loadLogs()} disabled={logs.loading}>
            {t('logs.refresh')}
          </button>
        </form>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginTop: 14 }}>
          <span style={{ color: 'var(--dim)', fontSize: 13 }}>{t('logs.filterLabel')}</span>
          {FILTERS.map(filter => (
            <button
              key={filter}
              type="button"
              className="tb-btn"
              aria-pressed={logs.typeFilter === filter}
              onClick={() => logs.handleTypeFilter(filter)}
              style={logs.typeFilter === filter ? { color: 'var(--accent)', borderColor: 'var(--accent)' } : undefined}
            >
              {filterLabel[filter]}
            </button>
          ))}
          <span style={{ marginLeft: 'auto', color: 'var(--dim)', fontSize: 13 }}>
            {t('logs.totalRecords', { count: logs.filteredCount })}
          </span>
        </div>
      </Card>

      <Card title={t('logs.accessLogs')}>
        {logs.searchMode && (
          <div style={{ color: 'var(--yellow)', marginBottom: 12, fontSize: 13 }}>
            {t('logs.searchResultsBadge', { count: logs.filteredCount, query: logs.searchQuery })}
          </div>
        )}
        {logs.error && (
          <div role="alert" style={{ color: 'var(--red)', marginBottom: 12 }}>
            {t('common.networkError')}: {logs.error}
          </div>
        )}
        <div className="tbl-wrap">
          <table className="tbl" style={{ minWidth: 760 }}>
            <thead>
              <tr>
                <th>{t('logs.time')}</th>
                <th>IP</th>
                <th>{t('logs.geo')}</th>
                <th>{t('logs.method')}</th>
                <th>{t('logs.path')}</th>
                <th>{t('logs.status')}</th>
                <th>{t('logs.type')}</th>
                <th>{t('logs.action')}</th>
              </tr>
            </thead>
            <tbody>
              {logs.pageLogs.map((log, index) => {
                const type = getLogType(log)
                return (
                  <tr key={String(log.request_id || `${log.timestamp}-${log.ip}-${index}`)}>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(log)}</td>
                    <td style={{ fontFamily: "'Share Tech Mono', monospace" }}>{String(log.ip || '—')}</td>
                    <td>{[log.country, log.city].filter(Boolean).join(' / ') || '—'}</td>
                    <td>{String(log.method || '—')}</td>
                    <td title={String(log.path || log.url || '')} style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {String(log.path || log.url || '—')}
                    </td>
                    <td>{String(log.status ?? '—')}</td>
                    <td><Badge variant={getBadgeVariant(type)}>{t(`logs.type_${type}`)}</Badge></td>
                    <td>
                      <button className="tb-btn" type="button" onClick={() => void logs.openDetail(log)}>
                        {t('logs.detail')}
                      </button>
                    </td>
                  </tr>
                )
              })}
              {!logs.loading && logs.pageLogs.length === 0 && (
                <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--dim)', padding: 28 }}>
                  {logs.error ? t('logs.loadFailed') : t('logs.noLogData')}
                </td></tr>
              )}
              {logs.loading && logs.pageLogs.length === 0 && (
                <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--dim)', padding: 28 }}>
                  {t('topbar.loading')}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
        <Pagination
          page={logs.page}
          totalPages={logs.totalPages}
          onPageChange={logs.handleGoPage}
          disabled={logs.loading || logs.filteredCount === 0}
          totalHint={t('logs.totalRecords', { count: logs.filteredCount })}
        />
      </Card>

      <Modal open={logs.modalOpen} onClose={logs.closeDetail} title={t('logDetail.title')} width="820px">
        {logs.selectedLog && (
          <>
            <div style={{ marginBottom: 20 }}>
              {Object.entries(logs.selectedLog)
                .filter(([key]) => key !== 'rrweb' && !key.startsWith('_'))
                .map(([key, value]) => (
                  <div className="detail-row" key={key}>
                    <div className="detail-key">{key.replace(/_/g, ' ')}</div>
                    <div className="detail-val" style={{ whiteSpace: 'pre-wrap' }}>{printable(value)}</div>
                  </div>
                ))}
            </div>
            <div style={{ color: 'var(--accent)', fontWeight: 700, letterSpacing: 1, marginBottom: 10 }}>
              {t('logDetail.userSessionReplay')}
            </div>
            <div ref={playerRef} style={{ minHeight: 72, display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'auto', border: '1px solid var(--border)', borderRadius: 6, background: '#000' }}>
              {logs.rrwebLoading && <span style={{ color: 'var(--dim)' }}>{t('logDetail.loadingReplay')}</span>}
              {!logs.rrwebLoading && !logs.hasReplayData && <span style={{ color: 'var(--dim)' }}>{t('logDetail.noReplayAvailable')}</span>}
            </div>
          </>
        )}
      </Modal>
    </div>
  )
}
