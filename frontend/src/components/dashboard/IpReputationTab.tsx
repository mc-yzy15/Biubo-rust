import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card } from '../ui/Card'
import { Badge } from '../ui/Badge'
import type { ProviderConfig, IpReputationResult, CacheStats, ReputationProvider } from '../../types'

const DEFAULT_PROVIDERS: ProviderConfig[] = [
  { id: 'abuseipdb', name: 'AbuseIPDB', enabled: false, apiKey: '' },
  { id: 'greynoise', name: 'GreyNoise', enabled: false, apiKey: '' },
  { id: 'virustotal', name: 'VirusTotal', enabled: false, apiKey: '' },
  { id: 'spamhaus', name: 'Spamhaus', enabled: false, apiKey: '' },
  { id: 'ipinfo', name: 'IPinfo', enabled: false, apiKey: '' },
]

interface ToastItem {
  id: number
  message: string
  type: 'ok' | 'err'
}

let toastId = 0

export function IpReputationTab() {
  const { t } = useTranslation()
  const [providers, setProviders] = useState<ProviderConfig[]>(DEFAULT_PROVIDERS)
  const [lookupIp, setLookupIp] = useState('')
  const [lookupResult, setLookupResult] = useState<IpReputationResult | null>(null)
  const [lookupLoading, setLookupLoading] = useState(false)
  const [cacheStats, setCacheStats] = useState<CacheStats | null>(null)

  const [toasts, setToasts] = useState<ToastItem[]>([])

  const showToast = useCallback((message: string, type: 'ok' | 'err') => {
    const id = ++toastId
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id))
    }, 3000)
  }, [])

  const loadProviders = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/ip-reputation/providers')
      if (res.ok) {
        const data = await res.json()
        if (Array.isArray(data)) {
          setProviders(data)
        }
      }
    } catch {
    }
  }, [])

  const loadCacheStats = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/ip-reputation/cache-stats')
      if (res.ok) {
        const data = await res.json()
        setCacheStats(data)
      }
    } catch {
    }
  }, [])

  useEffect(() => {
    loadProviders()
    loadCacheStats()
  }, [loadProviders, loadCacheStats])

  const handleToggleProvider = useCallback(async (id: ReputationProvider, enabled: boolean) => {
    setProviders((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled } : p))
    )
    try {
      await fetch('/api/v1/ip-reputation/providers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, enabled }),
      })
      showToast(t('phase3.ip_reputation.saving'), 'ok')
    } catch {
      showToast(t('common.networkError'), 'err')
    }
  }, [showToast, t])

  const handleApiKeyChange = useCallback((id: ReputationProvider, apiKey: string) => {
    setProviders((prev) =>
      prev.map((p) => (p.id === id ? { ...p, apiKey } : p))
    )
  }, [])

  const handleSaveApiKey = useCallback(async (id: ReputationProvider, apiKey: string) => {
    try {
      await fetch('/api/v1/ip-reputation/providers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, apiKey }),
      })
      showToast(t('settings.saveSuccess'), 'ok')
    } catch {
      showToast(t('common.networkError'), 'err')
    }
  }, [showToast, t])

  const handleLookup = useCallback(async () => {
    if (!lookupIp.trim()) {
      showToast(t('common.pleaseEnterIP'), 'err')
      return
    }
    setLookupLoading(true)
    setLookupResult(null)
    try {
      const res = await fetch(`/api/v1/ip-reputation/${encodeURIComponent(lookupIp.trim())}`)
      if (res.ok) {
        const data = await res.json()
        setLookupResult(data)
      } else {
        showToast(t('common.networkError'), 'err')
      }
    } catch {
      showToast(t('common.networkError'), 'err')
    } finally {
      setLookupLoading(false)
    }
  }, [lookupIp, showToast, t])

  const riskColor = (level: string): 'green' | 'yellow' | 'blue' | 'red' => {
    switch (level) {
      case 'clean': return 'green'
      case 'low': return 'blue'
      case 'medium': return 'yellow'
      case 'high': return 'red'
      default: return 'blue'
    }
  }

  const riskLabel = (level: string) => {
    switch (level) {
      case 'clean': return t('phase3.ip_reputation.clean')
      case 'low': return t('phase3.ip_reputation.low_risk')
      case 'medium': return t('phase3.ip_reputation.medium_risk')
      case 'high': return t('phase3.ip_reputation.high_risk')
      default: return level
    }
  }

  return (
    <div className="tab-panel" id="tab-ipreputation">
      <div className="grid-2" style={{ marginBottom: 20 }}>
        <Card title={t('phase3.ip_reputation.provider_config')}>
          {providers.map((p) => (
            <div
              key={p.id}
              className="st-proxy-row"
              style={{ alignItems: 'center', marginBottom: 10 }}
            >
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={p.enabled}
                  onChange={(e) => handleToggleProvider(p.id, e.target.checked)}
                  style={{ accentColor: 'var(--accent)', width: 16, height: 16 }}
                />
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 13 }}>
                  {t(`phase3.providers.${p.id}`)}
                </span>
              </label>
              <input
                type="password"
                placeholder={t('phase3.ip_reputation.api_key')}
                value={p.apiKey}
                onChange={(e) => handleApiKeyChange(p.id, e.target.value)}
                style={{
                  flex: 2,
                  background: 'rgba(0, 100, 180, 0.1)',
                  border: '1px solid var(--border)',
                  borderRadius: 4,
                  padding: '6px 10px',
                  color: 'var(--text)',
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 13,
                  outline: 'none',
                }}
              />
              <button
                className="st-btn-save"
                style={{ fontSize: 11, padding: '6px 14px', letterSpacing: '1px' }}
                onClick={() => handleSaveApiKey(p.id, p.apiKey)}
              >
                {t('system.save')}
              </button>
            </div>
          ))}
        </Card>

        <Card title={t('phase3.ip_reputation.cache_stats')}>
          {cacheStats ? (
            <>
              <div className="detail-row">
                <div className="detail-key">{t('phase3.ip_reputation.cache_size')}</div>
                <div className="detail-val">{cacheStats.cacheSize}</div>
              </div>
              <div className="detail-row">
                <div className="detail-key">{t('phase3.ip_reputation.hit_rate')}</div>
                <div className="detail-val">{(cacheStats.hitRate * 100).toFixed(1)}%</div>
              </div>
              <div className="detail-row">
                <div className="detail-key">{t('phase3.ip_reputation.clean_count')}</div>
                <div className="detail-val" style={{ color: 'var(--green)' }}>{cacheStats.cleanCount}</div>
              </div>
              <div className="detail-row">
                <div className="detail-key">{t('phase3.ip_reputation.flagged_count')}</div>
                <div className="detail-val" style={{ color: 'var(--red)' }}>{cacheStats.flaggedCount}</div>
              </div>
            </>
          ) : (
            <div style={{ color: 'var(--dim)', fontSize: 12, textAlign: 'center', padding: '20px 0' }}>
              {t('dashboard.noData')}
            </div>
          )}
        </Card>
      </div>

      <Card title={t('phase3.ip_reputation.lookup')}>
        <div className="add-form" style={{ marginBottom: 16 }}>
          <input
            type="text"
            placeholder={t('phase3.ip_reputation.lookup_placeholder')}
            value={lookupIp}
            onChange={(e) => setLookupIp(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleLookup() }}
          />
          <button
            onClick={handleLookup}
            disabled={lookupLoading}
          >
            {lookupLoading ? t('topbar.loading') : t('phase3.ip_reputation.check_btn')}
          </button>
        </div>

        {lookupResult && (
          <>
            <div className="detail-row">
              <div className="detail-key">IP</div>
              <div className="detail-val" style={{ fontFamily: "'Share Tech Mono', monospace" }}>
                {lookupResult.ip}
              </div>
            </div>
            <div className="detail-row">
              <div className="detail-key">{t('phase3.ip_reputation.score')}</div>
              <div className="detail-val" style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 24 }}>
                {lookupResult.score}/100
              </div>
            </div>
            <div className="detail-row">
              <div className="detail-key">{t('phase3.ip_reputation.risk_level')}</div>
              <div className="detail-val">
                <Badge variant={riskColor(lookupResult.riskLevel)}>
                  {riskLabel(lookupResult.riskLevel)}
                </Badge>
              </div>
            </div>
            {lookupResult.reports !== undefined && (
              <div className="detail-row">
                <div className="detail-key">{t('phase3.ip_reputation.reports')}</div>
                <div className="detail-val">{lookupResult.reports}</div>
              </div>
            )}
            {lookupResult.sources && lookupResult.sources.length > 0 && (
              <div className="detail-row">
                <div className="detail-key">{t('phase3.ip_reputation.sources')}</div>
                <div className="detail-val">{lookupResult.sources.join(', ')}</div>
              </div>
            )}
            {lookupResult.details && (
              <div className="detail-row">
                <div className="detail-key">{t('phase3.rule_browser.description')}</div>
                <div className="detail-val">{lookupResult.details}</div>
              </div>
            )}
          </>
        )}
      </Card>

      <div className="toast">
        {toasts.map((item) => (
          <div key={item.id} className={`toast-item ${item.type}`}>
            {item.message}
          </div>
        ))}
      </div>
    </div>
  )
}
