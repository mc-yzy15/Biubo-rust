import { useTranslation } from 'react-i18next'
import { SettingsConfig } from '../../types'

interface LLMConfigProps {
  config: SettingsConfig
  onChange: (field: 'API_KEY' | 'LLM_MODEL' | 'LLM_BASE_URL', value: string) => void
}

export function LLMConfig({ config, onChange }: LLMConfigProps) {
  const { t } = useTranslation()

  return (
    <div className="st-group">
      <div className="st-header">{t('settings.llmConfig')}</div>
      <div className="st-row">
        <div className="st-lbl">{t('settings.apiKey')}</div>
        <div className="st-ctrl">
          <input
            type="password"
            value={config.API_KEY}
            onChange={(e) => onChange('API_KEY', e.target.value)}
            placeholder="AI detection API Key"
          />
        </div>
      </div>
      <div className="st-row">
        <div className="st-lbl">{t('settings.model')}</div>
        <div className="st-ctrl">
          <input
            type="text"
            value={config.LLM_MODEL}
            onChange={(e) => onChange('LLM_MODEL', e.target.value)}
            placeholder="qwen-plus"
          />
        </div>
      </div>
      <div className="st-row">
        <div className="st-lbl">{t('settings.baseUrl')}</div>
        <div className="st-ctrl">
          <input
            type="text"
            value={config.LLM_BASE_URL}
            onChange={(e) => onChange('LLM_BASE_URL', e.target.value)}
            placeholder="https://..."
          />
        </div>
      </div>
    </div>
  )
}
