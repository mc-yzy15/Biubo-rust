import { useState, useCallback, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Modal } from '../ui/Modal'
import { PluginConfigModal, PluginConfigData } from './PluginConfigModal'

interface Plugin {
  id: string
  name: string
  version: string
  description: string
  type: string
  enabled: boolean
  config?: PluginConfigData
}

interface ToastItem {
  id: number
  message: string
  type: 'ok' | 'err'
}

let toastId = 0

export function PluginManager() {
  const { t } = useTranslation()
  const [plugins, setPlugins] = useState<Plugin[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloading, setReloading] = useState(false)
  const [configModalPlugin, setConfigModalPlugin] = useState<Plugin | null>(null)
  const [deleteModalPlugin, setDeleteModalPlugin] = useState<Plugin | null>(null)
  const [toasts, setToasts] = useState<ToastItem[]>([])

  const showToast = useCallback((message: string, type: 'ok' | 'err') => {
    const id = ++toastId
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id))
    }, 3000)
  }, [])

  const fetchPlugins = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const response = await fetch('/api/plugins')
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      const data = await response.json()
      setPlugins(Array.isArray(data) ? data : data.plugins || [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchPlugins()
  }, [fetchPlugins])

  const handleToggle = async (plugin: Plugin) => {
    try {
      const newEnabled = !plugin.enabled
      const response = await fetch(`/api/plugins/${plugin.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newEnabled }),
      })
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      setPlugins((prev) =>
        prev.map((p) => (p.id === plugin.id ? { ...p, enabled: newEnabled } : p))
      )
      showToast(
        t('plugins.toggleSuccess', { action: newEnabled ? t('plugins.enable') : t('plugins.disable') }),
        'ok'
      )
    } catch (err) {
      showToast(t('plugins.toggleFailed'), 'err')
    }
  }

  const handleDelete = async () => {
    if (!deleteModalPlugin) return
    try {
      const response = await fetch(`/api/plugins/${deleteModalPlugin.id}`, {
        method: 'DELETE',
      })
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      setPlugins((prev) => prev.filter((p) => p.id !== deleteModalPlugin.id))
      showToast(t('plugins.deleteSuccess'), 'ok')
    } catch (err) {
      showToast(t('plugins.deleteFailed'), 'err')
    } finally {
      setDeleteModalPlugin(null)
    }
  }

  const handleReload = async () => {
    try {
      setReloading(true)
      const response = await fetch('/api/plugins/reload', { method: 'POST' })
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      await fetchPlugins()
      showToast(t('plugins.reloadSuccess'), 'ok')
    } catch (err) {
      showToast(t('plugins.reloadFailed'), 'err')
    } finally {
      setReloading(false)
    }
  }

  const handleSaveConfig = async (config: PluginConfigData): Promise<boolean> => {
    if (!configModalPlugin) return false
    try {
      const response = await fetch(`/api/plugins/${configModalPlugin.id}/config`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config }),
      })
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      setPlugins((prev) =>
        prev.map((p) => (p.id === configModalPlugin.id ? { ...p, config } : p))
      )
      showToast(t('plugins.saveConfigSuccess'), 'ok')
      return true
    } catch (err) {
      showToast(t('plugins.saveConfigFailed'), 'err')
      return false
    }
  }

  if (loading && plugins.length === 0) {
    return (
      <div className="tab-panel" id="tab-plugins">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--dim)' }}>
          {t('plugins.loading')}
        </div>
      </div>
    )
  }

  if (error && plugins.length === 0) {
    return (
      <div className="tab-panel" id="tab-plugins">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--red)' }}>
          {t('plugins.error')}: {error}
        </div>
      </div>
    )
  }

  return (
    <div className="tab-panel" id="tab-plugins">
      <div className="card settings-card">
        <div className="card-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: '14px', height: '14px' }}>
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
            <polyline points="3.27,6.96 12,12.01 20.73,6.96" />
            <line x1="12" y1="22.08" x2="12" y2="12" />
          </svg>
          {t('plugins.title')}
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '16px' }}>
          <button
            className="ctrl-btn"
            onClick={handleReload}
            disabled={reloading}
          >
            {reloading ? 'Reloading...' : t('plugins.reload')}
          </button>
        </div>

        {plugins.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--dim)' }}>
            {t('plugins.noPlugins')}
          </div>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>{t('plugins.name')}</th>
                  <th>{t('plugins.version')}</th>
                  <th>{t('plugins.type')}</th>
                  <th>{t('plugins.status')}</th>
                  <th>{t('plugins.description')}</th>
                  <th>{t('ipManage.action')}</th>
                </tr>
              </thead>
              <tbody>
                {plugins.map((plugin) => (
                  <tr key={plugin.id}>
                    <td style={{ fontWeight: 600 }}>{plugin.name}</td>
                    <td>
                      <span className="badge badge-blue">{plugin.version}</span>
                    </td>
                    <td>
                      <span className={`badge ${plugin.type === 'detection' ? 'badge-green' : 'badge-yellow'}`}>
                        {plugin.type === 'detection' ? t('plugins.detection') : plugin.type === 'exporter' ? t('plugins.exporter') : plugin.type}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${plugin.enabled ? 'badge-green' : 'badge-red'}`}>
                        {plugin.enabled ? t('plugins.enabled') : t('plugins.disabled')}
                      </span>
                    </td>
                    <td style={{ maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {plugin.description || '-'}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '6px' }}>
                        <button
                          className={`ctrl-btn ${plugin.enabled ? 'danger' : ''}`}
                          onClick={() => handleToggle(plugin)}
                          style={{ padding: '4px 10px', fontSize: '11px' }}
                        >
                          {plugin.enabled ? t('plugins.disable') : t('plugins.enable')}
                        </button>
                        <button
                          className="ctrl-btn"
                          onClick={() => setConfigModalPlugin(plugin)}
                          style={{ padding: '4px 10px', fontSize: '11px' }}
                        >
                          {t('plugins.config')}
                        </button>
                        <button
                          className="ip-del"
                          onClick={() => setDeleteModalPlugin(plugin)}
                          style={{ padding: '4px 10px', fontSize: '11px' }}
                        >
                          {t('plugins.delete')}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <Modal
        open={!!deleteModalPlugin}
        onClose={() => setDeleteModalPlugin(null)}
        title={t('plugins.delete')}
        width="450px"
      >
        <p style={{ marginBottom: '20px', color: 'var(--text)' }}>
          {deleteModalPlugin && t('plugins.confirmDelete', { name: deleteModalPlugin.name })}
        </p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
          <button
            className="ctrl-btn"
            onClick={() => setDeleteModalPlugin(null)}
          >
            {t('plugins.cancel')}
          </button>
          <button
            className="ip-del"
            onClick={handleDelete}
            style={{ padding: '8px 20px' }}
          >
            {t('plugins.delete')}
          </button>
        </div>
      </Modal>

      {configModalPlugin && (
        <PluginConfigModal
          open={!!configModalPlugin}
          onClose={() => setConfigModalPlugin(null)}
          pluginName={configModalPlugin.name}
          pluginType={configModalPlugin.type}
          initialConfig={configModalPlugin.config || {}}
          onSave={handleSaveConfig}
        />
      )}

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
