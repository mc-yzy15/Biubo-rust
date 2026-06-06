import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSettings } from '../../hooks/useSettings'
import { BasicConfig } from './BasicConfig'
import { ProxyManager } from './ProxyManager'
import { LLMConfig } from './LLMConfig'

interface ToastItem {
  id: number
  message: string
  type: 'ok' | 'err'
}

let toastId = 0

export function SettingsTab() {
  const { t } = useTranslation()
  const { config, proxyList, loading, saving, error, loadConfig, setProxyList, updateField, saveConfig } = useSettings()
  const [toasts, setToasts] = useState<ToastItem[]>([])

  useEffect(() => {
    loadConfig()
  }, [loadConfig])

  const showToast = (message: string, type: 'ok' | 'err') => {
    const id = ++toastId
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id))
    }, 3000)
  }

  const handleSave = async () => {
    const proxyMap = Object.fromEntries(
      proxyList.filter(p => p.domain && p.backend).map(p => [p.domain, p.backend])
    )
    if (Object.keys(proxyMap).length === 0) {
      showToast(t('settings.atLeastOneProxy'), 'err')
      return
    }

    const success = await saveConfig()
    if (success) {
      showToast(t('settings.saveSuccess'), 'ok')
    } else {
      showToast(t('settings.saveFailed'), 'err')
    }
  }

  const handleAddProxy = () => {
    setProxyList([...proxyList, { domain: '', backend: '' }])
  }

  const handleRemoveProxy = (index: number) => {
    setProxyList(proxyList.filter((_, i) => i !== index))
  }

  const handleProxyChange = (list: typeof proxyList) => {
    setProxyList(list)
  }

  if (loading && !config) {
    return (
      <div className="tab-panel" id="tab-settings">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--dim)' }}>
          {t('topbar.loading')}
        </div>
      </div>
    )
  }

  if (error && !config) {
    return (
      <div className="tab-panel" id="tab-settings">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--red)' }}>
          {t('common.networkError')}: {error}
        </div>
      </div>
    )
  }

  if (!config) {
    return null
  }

  return (
    <div className="tab-panel" id="tab-settings">
      <div className="card settings-card">
        <div className="card-title">{t('settings.title')}</div>

        <BasicConfig
          config={config}
          onChange={(value) => updateField('DASHBOARD_PASSWORD', value)}
        />

        <ProxyManager
          proxyList={proxyList}
          onChange={handleProxyChange}
          onAdd={handleAddProxy}
          onRemove={handleRemoveProxy}
        />

        <LLMConfig
          config={config}
          onChange={(field, value) => updateField(field, value)}
        />

        <div className="st-footer">
          <button className="st-btn-save" onClick={handleSave} disabled={saving}>
            {saving ? 'Saving...' : t('settings.saveConfig')}
          </button>
        </div>
      </div>

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
