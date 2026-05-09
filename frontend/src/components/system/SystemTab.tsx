import { useContext, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { AppContext } from '../../context/AppContext'
import { useSystemStatus } from '../../hooks/useSystemStatus'
import { GaugeCard } from './GaugeCard'
import { SystemInfoList } from './SystemInfoList'
import { WafStatusEditor } from './WafStatusEditor'

interface ToastItem {
  id: number
  message: string
  type: 'ok' | 'err'
}

let toastId = 0

export function SystemTab() {
  const { t } = useTranslation()
  const ctx = useContext(AppContext)
  const currentHost = ctx?.currentHost ?? null
  const { metrics, wafStatus, loading, error, refetch } = useSystemStatus(currentHost)
  const [toasts, setToasts] = useState<ToastItem[]>([])

  const showToast = useCallback((message: string, type: 'ok' | 'err') => {
    const id = ++toastId
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id))
    }, 3000)
  }, [])

  const handleSaved = useCallback(() => {
    refetch()
  }, [refetch])

  if (!currentHost) {
    return (
      <div className="tab-panel" id="tab-system">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--dim)' }}>
          {t('ipManage.selectHost')}
        </div>
      </div>
    )
  }

  if (loading && !metrics) {
    return (
      <div className="tab-panel" id="tab-system">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--dim)' }}>
          {t('topbar.loading')}
        </div>
      </div>
    )
  }

  if (error && !metrics) {
    return (
      <div className="tab-panel" id="tab-system">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--red)' }}>
          {t('common.networkError')}: {error}
        </div>
      </div>
    )
  }

  return (
    <div className="tab-panel" id="tab-system">
      {/* Row 1: 3 gauge cards (CPU/Memory/Disk) */}
      <div className="grid-3" style={{ marginBottom: 20 }}>
        <GaugeCard
          label={t('system.cpuUsage')}
          percent={metrics?.cpu?.percent ?? 0}
          subtitle={`${metrics?.cpu?.cores ?? '-'} ${t('system.cores')}`}
          colorVariant="blue"
        />
        <GaugeCard
          label={t('system.memoryUsage')}
          percent={metrics?.memory?.percent ?? 0}
          subtitle={`${metrics?.memory?.used_gb?.toFixed(1) ?? '-'} / ${metrics?.memory?.total_gb?.toFixed(1) ?? '-'} GB`}
          colorVariant="green"
        />
        <GaugeCard
          label={t('system.diskUsage')}
          percent={metrics?.disk?.percent ?? 0}
          subtitle={`${metrics?.disk?.used_gb?.toFixed(1) ?? '-'} / ${metrics?.disk?.total_gb?.toFixed(1) ?? '-'} GB`}
          colorVariant="red"
        />
      </div>

      {/* Row 2: System info + WAF status */}
      <div className="grid-2">
        <SystemInfoList metrics={metrics} />
        <WafStatusEditor
          wafStatus={wafStatus}
          host={currentHost}
          onSaved={handleSaved}
          showToast={showToast}
        />
      </div>

      {/* Toast notifications */}
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
