import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

interface QueueStats {
  capacity: number
  queued: number
  in_flight?: number
  submitted?: number
  completed?: number
  rejected?: number
  depth?: number
  written?: number
  dropped?: number
  security_dropped?: number
  write_errors?: number
}

interface RuntimeResponse {
  status?: string
  data?: {
    detection_queue: QueueStats | null
    log_queue: QueueStats
    advanced_rules_shadow_mode?: boolean
    advanced_rules_shadow_stats?: Record<string, number>
  }
}

function QueueCard({ title, queue }: { title: string; queue?: QueueStats | null }) {
  const { t } = useTranslation()
  if (!queue) {
    return <div className="card"><div className="card-title">{title}</div><div>{t('system.unavailable')}</div></div>
  }

  const depth = queue.queued ?? queue.depth ?? 0
  const percent = queue.capacity > 0 ? Math.min(100, (depth / queue.capacity) * 100) : 0
  const degraded = percent >= 90 || (queue.dropped ?? 0) > 0 || (queue.security_dropped ?? 0) > 0 || (queue.write_errors ?? 0) > 0

  return (
    <div className="card">
      <div className="card-title">{title}</div>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, margin: '12px 0 6px' }}>
        <strong>{depth.toLocaleString()} / {queue.capacity.toLocaleString()}</strong>
        <span style={{ color: degraded ? 'var(--red)' : 'var(--green)' }}>{degraded ? t('system.degraded') : t('system.healthy')}</span>
      </div>
      <div className="progress-bar"><div className={`progress-fill ${degraded ? 'red' : 'green'}`} style={{ width: `${percent}%` }} /></div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 6, marginTop: 12, color: 'var(--dim)', fontSize: 12 }}>
        {queue.in_flight !== undefined && <span>{t('system.inFlight')}: {queue.in_flight}</span>}
        {queue.completed !== undefined && <span>{t('system.completed')}: {queue.completed}</span>}
        {queue.rejected !== undefined && <span>{t('system.rejected')}: {queue.rejected}</span>}
        {queue.written !== undefined && <span>{t('system.written')}: {queue.written}</span>}
        {queue.dropped !== undefined && <span>{t('system.dropped')}: {queue.dropped}</span>}
        {queue.security_dropped !== undefined && <span>{t('system.securityDropped')}: {queue.security_dropped}</span>}
        {queue.write_errors !== undefined && <span>{t('system.writeErrors')}: {queue.write_errors}</span>}
      </div>
    </div>
  )
}

export function RuntimeHealth() {
  const { t } = useTranslation()
  const [runtime, setRuntime] = useState<RuntimeResponse['data'] | null>(null)

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const response = await fetch('/biubo-cgi/api/biubo/dashboard/runtime')
        if (!response.ok) return
        const json: RuntimeResponse = await response.json()
        if (active && json.data) setRuntime(json.data)
      } catch {
        // Runtime telemetry is supplementary; keep the rest of the system page usable.
      }
    }
    void load()
    const timer = window.setInterval(load, 5000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [])

  return (
    <section style={{ marginTop: 20 }}>
      <h3 style={{ margin: '0 0 12px' }}>{t('system.runtimeQueues')}</h3>
      <div className="grid-2">
        <QueueCard title={t('system.detectionQueue')} queue={runtime?.detection_queue} />
        <QueueCard title={t('system.logQueue')} queue={runtime?.log_queue} />
      </div>
      {runtime?.advanced_rules_shadow_mode && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">{t('system.ruleShadowMode')}</div>
          <div style={{ color: 'var(--yellow)', marginTop: 8 }}>{t('system.ruleShadowEnabled')}</div>
          <div style={{ display: 'flex', gap: 20, marginTop: 10, color: 'var(--dim)', fontSize: 13 }}>
            <span>{t('system.shadowMatchedRequests')}: {(runtime.advanced_rules_shadow_stats?.shadow_matched_requests ?? 0).toLocaleString()}</span>
            <span>{t('system.shadowRuleHits')}: {(runtime.advanced_rules_shadow_stats?.shadow_rule_hits ?? 0).toLocaleString()}</span>
          </div>
        </div>
      )}
    </section>
  )
}
