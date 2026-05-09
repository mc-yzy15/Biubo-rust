import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { Log } from '../../types'
import type { AttackNode, AttackData, GeoCoords } from '../../hooks/useGlobeData'

interface IPSearchProps {
  onSearch: (ip: string, from: string, to: string) => Promise<void>
  results: Log[]
  loading: boolean
  onHighlight: (lat: number, lng: number, type: string) => void
  getGeo: (log: Log) => Promise<GeoCoords>
  logToAttack: (log: Log, server: AttackNode) => Promise<AttackData>
  pushAttack: (attack: AttackData) => void
  serverNode: AttackNode
}

export function IPSearch({ onSearch, results, loading, onHighlight, getGeo, logToAttack, pushAttack, serverNode }: IPSearchProps) {
  const { t } = useTranslation()
  const [ip, setIp] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')

  const handleSearch = () => {
    if (!ip.trim()) return
    onSearch(ip.trim(), dateFrom, dateTo)
  }

  const handleResultClick = async (log: Log) => {
    const lat = parseFloat(String((log as any).lat || 0))
    const lng = parseFloat(String((log as any).lon || (log as any).lng || 0))
    if (lat && lng) {
      onHighlight(lat, lng, log.type || 'Unknown')
      const geo = await getGeo(log)
      const attack = await logToAttack({ ...log, lat: geo.lat, lon: geo.lng } as unknown as Log, serverNode)
      attack._sc = '#ffd700'
      attack._ttl = 10000
      pushAttack(attack)
    }
  }

  return (
    <div className="g-card">
      <div className="g-card-title">{t('globe.ipSearch')}</div>
      <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
        <input
          placeholder="IP Address"
          value={ip}
          onChange={e => setIp(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSearch()}
          style={{ flex: 1, background: 'rgba(0,100,180,0.1)', border: '1px solid var(--border)', borderRadius: 4, padding: '6px 10px', color: 'var(--text)', fontFamily: "'Share Tech Mono', monospace", fontSize: 11, outline: 'none' }}
        />
        <button
          onClick={handleSearch}
          disabled={loading}
          style={{ background: 'rgba(0,200,255,0.1)', border: '1px solid var(--accent)', borderRadius: 4, padding: '6px 10px', color: 'var(--accent)', fontSize: 11, cursor: 'pointer', fontFamily: "'Rajdhani', sans-serif", fontWeight: 700 }}
        >
          {t('logs.search')}
        </button>
      </div>
      <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
        <input
          type="date"
          value={dateFrom}
          onChange={e => setDateFrom(e.target.value)}
          style={{ flex: 1, background: 'rgba(0,100,180,0.1)', border: '1px solid var(--border)', borderRadius: 4, padding: '5px 8px', color: 'var(--text)', fontSize: 11, outline: 'none' }}
        />
        <input
          type="date"
          value={dateTo}
          onChange={e => setDateTo(e.target.value)}
          style={{ flex: 1, background: 'rgba(0,100,180,0.1)', border: '1px solid var(--border)', borderRadius: 4, padding: '5px 8px', color: 'var(--text)', fontSize: 11, outline: 'none' }}
        />
      </div>
      <div style={{ fontSize: 11, color: 'var(--dim)', maxHeight: 120, overflowY: 'auto' }}>
        {loading ? (
          <div style={{ color: 'var(--dim)' }}>{t('logs.searching')}</div>
        ) : results.length === 0 && !loading ? (
          <div style={{ color: 'var(--dim)' }}>{t('globe.noRecordsFound')}</div>
        ) : (
          results.map((log, idx) => {
            const ts = log.timestamp ? new Date(log.timestamp * 1000).toLocaleString() : '-'
            const type = String(log.attack_type || log.type || '-')
            const path = String(log.path || log.url || '-').slice(0, 30)
            const country = String(log.country || '-')
            return (
              <div
                key={idx}
                style={{ padding: '4px 0', borderBottom: '1px solid rgba(0,200,255,0.08)', cursor: 'pointer' }}
                onClick={() => handleResultClick(log)}
              >
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: 'var(--accent)' }}>{ts}</div>
                <div style={{ fontSize: 10, color: 'var(--dim)' }}>{type} &middot; {country} &middot; {path}</div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
