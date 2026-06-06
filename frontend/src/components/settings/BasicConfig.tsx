import { useTranslation } from 'react-i18next'
import { SettingsConfig } from '../../types'

interface BasicConfigProps {
  config: SettingsConfig
  onChange: (value: string) => void
}

export function BasicConfig({ config, onChange }: BasicConfigProps) {
  const { t } = useTranslation()

  return (
    <div className="st-group">
      <div className="st-header">{t('settings.basicConfig')}</div>
      <div className="st-row">
        <div className="st-lbl">{t('settings.adminPassword')}</div>
        <div className="st-ctrl">
          <input
            type="password"
            value={config.DASHBOARD_PASSWORD}
            onChange={(e) => onChange(e.target.value)}
            placeholder={t('settings.leaveEmpty')}
          />
        </div>
      </div>
    </div>
  )
}
