import { useState, useCallback } from 'react'
import { api } from '../api/client'
import { SettingsConfig, ProxySite } from '../types'

const API_ENDPOINT = '/biubo/config'

function proxyMapToArray(map: Record<string, string>): ProxySite[] {
  return Object.entries(map || {}).map(([domain, backend]) => ({ domain, backend }))
}

function proxyArrayToMap(list: ProxySite[]): Record<string, string> {
  const map: Record<string, string> = {}
  list.forEach(({ domain, backend }) => {
    if (domain && backend) map[domain] = backend
  })
  return map
}

export interface UseSettingsReturn {
  config: SettingsConfig | null
  proxyList: ProxySite[]
  loading: boolean
  saving: boolean
  error: string | null
  loadConfig: () => Promise<void>
  setProxyList: (list: ProxySite[]) => void
  updateField: <K extends keyof SettingsConfig>(key: K, value: SettingsConfig[K]) => void
  saveConfig: () => Promise<boolean>
}

export function useSettings(): UseSettingsReturn {
  const [config, setConfig] = useState<SettingsConfig | null>(null)
  const [proxyList, setProxyList] = useState<ProxySite[]>([])
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadConfig = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.get<{ status: string; data: SettingsConfig }>(API_ENDPOINT)
      if (res.status === 'success' && res.data) {
        setConfig(res.data)
        setProxyList(proxyMapToArray(res.data.PROXY_MAP || {}))
      } else {
        setError('Failed to load config')
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }, [])

  const updateField = useCallback(<K extends keyof SettingsConfig>(key: K, value: SettingsConfig[K]) => {
    setConfig((prev) => (prev ? { ...prev, [key]: value } : prev))
  }, [])

  const saveConfig = useCallback(async (): Promise<boolean> => {
    if (!config) return false

    const proxyMap = proxyArrayToMap(proxyList)
    if (Object.keys(proxyMap).length === 0) return false

    setSaving(true)
    setError(null)
    try {
      const payload = {
        DASHBOARD_PASSWORD: config.DASHBOARD_PASSWORD || '',
        API_KEY: config.API_KEY || '',
        LLM_MODEL: config.LLM_MODEL || '',
        LLM_BASE_URL: config.LLM_BASE_URL || '',
        PROXY_MAP: proxyMap,
      }

      const res = await api.post<{ status: string; msg?: string }>(API_ENDPOINT, payload)
      if (res.status === 'success') {
        await loadConfig()
        return true
      } else {
        setError(res.msg || 'Save failed')
        return false
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Network error')
      return false
    } finally {
      setSaving(false)
    }
  }, [config, proxyList, loadConfig])

  return {
    config,
    proxyList,
    loading,
    saving,
    error,
    loadConfig,
    setProxyList,
    updateField,
    saveConfig,
  }
}
