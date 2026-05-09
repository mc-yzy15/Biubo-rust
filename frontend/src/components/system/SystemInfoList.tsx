import { useTranslation } from 'react-i18next'
import { Card } from '../ui/Card'
import type { SystemMetrics } from '../../hooks/useSystemStatus'

export interface SystemInfoListProps {
  metrics: SystemMetrics | null
}

export function SystemInfoList({ metrics }: SystemInfoListProps) {
  const { t } = useTranslation()

  const rows = [
    { key: t('dashboard.os'), value: metrics?.os || '-' },
    { key: t('system.pythonVersion'), value: metrics?.python_version || '-' },
    { key: t('system.uptime'), value: metrics?.uptime || '-' },
    { key: t('system.currentTime'), value: metrics?.time || '-' },
  ]

  return (
    <Card title={t('system.systemInfo')}>
      {rows.map((row, idx) => (
        <div className="detail-row" key={idx}>
          <div className="detail-key">{row.key}</div>
          <div className="detail-val">{row.value}</div>
        </div>
      ))}
    </Card>
  )
}
