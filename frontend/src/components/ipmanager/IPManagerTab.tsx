import { useContext, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { AppContext } from '../../context/AppContext'
import { useIPManager } from '../../hooks/useIPManager'
import { Card } from '../ui/Card'
import { BlacklistPanel } from './BlacklistPanel'
import { WhitelistPanel } from './WhitelistPanel'

interface ToastItem {
  id: number
  message: string
  type: 'ok' | 'err'
}

let toastId = 0

export function IPManagerTab() {
  const { t } = useTranslation()
  const ctx = useContext(AppContext)
  const currentHost = ctx?.currentHost ?? null
  const { blacklist, whitelist, loading, banIP, unbanIP, addWhitelistIP, removeWhitelistIP } = useIPManager(currentHost)
  const [toasts, setToasts] = useState<ToastItem[]>([])

  const showToast = useCallback((message: string, type: 'ok' | 'err') => {
    const id = ++toastId
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id))
    }, 3000)
  }, [])

  const handleBan = useCallback(async (ip: string, reason: string) => {
    const success = await banIP(ip, reason)
    if (success) {
      showToast(t('ipManage.banSuccess').replace('{ip}', ip), 'ok')
    } else {
      showToast(t('ipManage.operationFailed'), 'err')
    }
    return success
  }, [banIP, showToast, t])

  const handleUnban = useCallback(async (ip: string) => {
    const success = await unbanIP(ip)
    if (success) {
      showToast(t('ipManage.unbanSuccess').replace('{ip}', ip), 'ok')
    } else {
      showToast(t('ipManage.operationFailed'), 'err')
    }
    return success
  }, [unbanIP, showToast, t])

  const handleAddWhitelist = useCallback(async (ip: string, note: string) => {
    const success = await addWhitelistIP(ip, note)
    if (success) {
      showToast(t('ipManage.whitelistSuccess').replace('{ip}', ip), 'ok')
    } else {
      showToast(t('ipManage.operationFailed'), 'err')
    }
    return success
  }, [addWhitelistIP, showToast, t])

  const handleRemoveWhitelist = useCallback(async (ip: string) => {
    const success = await removeWhitelistIP(ip)
    if (success) {
      showToast(t('ipManage.removeSuccess').replace('{ip}', ip), 'ok')
    } else {
      showToast(t('ipManage.operationFailed'), 'err')
    }
    return success
  }, [removeWhitelistIP, showToast, t])

  if (!currentHost) {
    return (
      <div className="tab-panel" id="tab-ipmanage">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--dim)' }}>
          {t('ipManage.selectHost')}
        </div>
      </div>
    )
  }

  return (
    <div className="tab-panel" id="tab-ipmanage">
      <div className="grid-2">
        <Card title={t('ipManage.blacklist')}>
          <BlacklistPanel
            entries={blacklist}
            loading={loading}
            onAdd={handleBan}
            onUnban={handleUnban}
          />
        </Card>

        <Card title={t('ipManage.whitelist')}>
          <WhitelistPanel
            entries={whitelist}
            loading={loading}
            onAdd={handleAddWhitelist}
            onRemove={handleRemoveWhitelist}
          />
        </Card>
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
