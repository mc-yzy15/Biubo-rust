import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Modal } from '../ui/Modal'

export interface PluginConfigData {
  patterns?: string[]
  endpoint?: string
  interval?: number
  [key: string]: unknown
}

export interface PluginConfigModalProps {
  open: boolean
  onClose: () => void
  pluginName: string
  pluginType: string
  initialConfig: PluginConfigData
  onSave: (config: PluginConfigData) => Promise<boolean>
}

export function PluginConfigModal({
  open,
  onClose,
  pluginName,
  pluginType,
  initialConfig,
  onSave,
}: PluginConfigModalProps) {
  const { t } = useTranslation()
  const isDetection = pluginType === 'detection'
  const isExporter = pluginType === 'exporter'

  const [patterns, setPatterns] = useState<string[]>(initialConfig.patterns || [])
  const [endpoint, setEndpoint] = useState(initialConfig.endpoint || '')
  const [interval, setInterval] = useState(initialConfig.interval || 60)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (open) {
      setPatterns(initialConfig.patterns || [])
      setEndpoint(initialConfig.endpoint || '')
      setInterval(initialConfig.interval || 60)
    }
  }, [open, initialConfig])

  const handleAddPattern = useCallback(() => {
    setPatterns((prev) => [...prev, ''])
  }, [])

  const handlePatternChange = useCallback((index: number, value: string) => {
    setPatterns((prev) => prev.map((p, i) => (i === index ? value : p)))
  }, [])

  const handleRemovePattern = useCallback((index: number) => {
    setPatterns((prev) => prev.filter((_, i) => i !== index))
  }, [])

  const handleSave = async () => {
    setSaving(true)
    try {
      const config: PluginConfigData = {}
      if (isDetection) {
        config.patterns = patterns.filter((p) => p.trim() !== '')
      }
      if (isExporter) {
        config.endpoint = endpoint
        config.interval = interval
      }
      const success = await onSave(config)
      if (success) {
        onClose()
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={`${t('plugins.config')} - ${pluginName}`}>
      {isDetection && (
        <div className="st-group">
          <div className="st-header">
            <i>🔍</i>
            {t('plugins.detection')}
          </div>
          {patterns.map((pattern, index) => (
            <div className="st-proxy-row" key={index}>
              <input
                type="text"
                value={pattern}
                onChange={(e) => handlePatternChange(index, e.target.value)}
                placeholder={t('plugins.patternPlaceholder')}
              />
              <button
                className="ip-del"
                onClick={() => handleRemovePattern(index)}
                type="button"
              >
                ×
              </button>
            </div>
          ))}
          <button className="st-btn-add" onClick={handleAddPattern} type="button">
            {t('plugins.addPattern')}
          </button>
        </div>
      )}

      {isExporter && (
        <div className="st-group">
          <div className="st-header">
            <i>📤</i>
            {t('plugins.exporter')}
          </div>
          <div className="st-row">
            <div className="st-lbl">{t('plugins.endpoint')}</div>
            <div className="st-ctrl">
              <input
                type="text"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="https://example.com/api"
              />
            </div>
          </div>
          <div className="st-row">
            <div className="st-lbl">{t('plugins.interval')}</div>
            <div className="st-ctrl">
              <input
                type="number"
                value={interval}
                onChange={(e) => setInterval(Number(e.target.value))}
                min="1"
              />
            </div>
          </div>
        </div>
      )}

      {!isDetection && !isExporter && (
        <div className="st-group">
          <div className="st-header">
            <i>⚙</i>
            {t('plugins.configLabel')}
          </div>
          <pre style={{ fontSize: '12px', color: 'var(--dim)', overflow: 'auto', maxHeight: '300px' }}>
            {JSON.stringify(initialConfig, null, 2)}
          </pre>
        </div>
      )}

      <div className="st-footer">
        <button className="ctrl-btn" onClick={onClose} disabled={saving}>
          {t('plugins.cancel')}
        </button>
        <button className="st-btn-save" onClick={handleSave} disabled={saving}>
          {saving ? 'Saving...' : t('plugins.saveConfig')}
        </button>
      </div>
    </Modal>
  )
}
