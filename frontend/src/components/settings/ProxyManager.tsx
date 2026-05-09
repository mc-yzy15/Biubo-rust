import { useTranslation } from 'react-i18next'
import { ProxySite } from '../../types'

interface ProxyManagerProps {
  proxyList: ProxySite[]
  onChange: (list: ProxySite[]) => void
  onAdd: () => void
  onRemove: (index: number) => void
}

export function ProxyManager({ proxyList, onChange, onAdd, onRemove }: ProxyManagerProps) {
  const { t } = useTranslation()

  const updateDomain = (index: number, value: string) => {
    const updated = [...proxyList]
    updated[index] = { ...updated[index], domain: value }
    onChange(updated)
  }

  const updateBackend = (index: number, value: string) => {
    const updated = [...proxyList]
    updated[index] = { ...updated[index], backend: value }
    onChange(updated)
  }

  return (
    <div className="st-group">
      <div className="st-header">{t('settings.proxyManagement')}</div>
      <div id="st-proxy-list">
        {proxyList.map((proxy, index) => (
          <div key={index} className="st-proxy-row">
            <input
              type="text"
              placeholder="Domain"
              value={proxy.domain}
              onChange={(e) => updateDomain(index, e.target.value)}
            />
            <input
              type="text"
              placeholder="Backend URL"
              value={proxy.backend}
              onChange={(e) => updateBackend(index, e.target.value)}
            />
            <button className="ip-del" style={{ height: 32 }} onClick={() => onRemove(index)}>✕</button>
          </div>
        ))}
      </div>
      <button className="st-btn-add" onClick={onAdd}>{t('settings.addProxySite')}</button>
    </div>
  )
}
