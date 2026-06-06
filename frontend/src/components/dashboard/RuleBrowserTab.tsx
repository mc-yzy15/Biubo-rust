import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card } from '../ui/Card'
import { Badge } from '../ui/Badge'
import type { Rule, RuleSeverity, RuleCategory } from '../../types'

const SEVERITY_COLORS: Record<RuleSeverity, 'red' | 'yellow' | 'blue' | 'green'> = {
  critical: 'red',
  high: 'red',
  medium: 'yellow',
  low: 'green',
}

const CATEGORY_LIST: RuleCategory[] = [
  'sqli', 'xss', 'rce', 'lfi', 'rfi', 'ssrf', 'bot', 'bruteforce', 'ddos', 'upload', 'scan', 'custom',
]

interface ToastItem {
  id: number
  message: string
  type: 'ok' | 'err'
}

let toastId = 0

export function RuleBrowserTab() {
  const { t } = useTranslation()
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [categoryFilter, setCategoryFilter] = useState<RuleCategory | ''>('')
  const [paranoiaLevel, setParanoiaLevel] = useState(1)
  const [savingLevel, setSavingLevel] = useState(false)
  const [showCustomRule, setShowCustomRule] = useState(false)
  const [newPattern, setNewPattern] = useState('')
  const [newCategory, setNewCategory] = useState<RuleCategory>('custom')
  const [newSeverity, setNewSeverity] = useState<RuleSeverity>('medium')
  const [newDescription, setNewDescription] = useState('')
  const [newMitreId, setNewMitreId] = useState('')

  const [toasts, setToasts] = useState<ToastItem[]>([])

  const showToast = useCallback((message: string, type: 'ok' | 'err') => {
    const id = ++toastId
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id))
    }, 3000)
  }, [])

  const loadRules = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const res = await fetch('/api/v1/rules')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setRules(Array.isArray(data) ? data : data.rules || [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadRules()
  }, [loadRules])

  const handleSaveParanoiaLevel = useCallback(async () => {
    setSavingLevel(true)
    try {
      await fetch('/api/v1/rules/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ paranoia_level: paranoiaLevel }),
      })
      showToast(t('settings.saveSuccess'), 'ok')
    } catch {
      showToast(t('common.networkError'), 'err')
    } finally {
      setSavingLevel(false)
    }
  }, [paranoiaLevel, showToast, t])

  const handleToggleRule = useCallback(async (rule: Rule) => {
    const newEnabled = !rule.enabled
    try {
      await fetch('/api/v1/rules/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: rule.id, enabled: newEnabled }),
      })
      setRules((prev) => prev.map((r) => (r.id === rule.id ? { ...r, enabled: newEnabled } : r)))
      showToast(t('phase3.rule_browser.toggle_rule').replace('{{id}}', rule.id), 'ok')
    } catch {
      showToast(t('common.networkError'), 'err')
    }
  }, [showToast, t])

  const handleCreateRule = useCallback(async () => {
    if (!newPattern.trim() || !newDescription.trim()) {
      showToast(t('common.cannotBeEmpty'), 'err')
      return
    }
    try {
      const res = await fetch('/api/v1/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pattern: newPattern.trim(),
          category: newCategory,
          severity: newSeverity,
          description: newDescription.trim(),
          mitre_id: newMitreId.trim() || undefined,
          paranoia_level: paranoiaLevel,
        }),
      })
      if (res.ok) {
        const created = await res.json()
        setRules((prev) => [created, ...prev])
        setShowCustomRule(false)
        setNewPattern('')
        setNewDescription('')
        setNewMitreId('')
        showToast(t('settings.saveSuccess'), 'ok')
      } else {
        showToast(t('common.networkError'), 'err')
      }
    } catch {
      showToast(t('common.networkError'), 'err')
    }
  }, [newPattern, newCategory, newSeverity, newDescription, newMitreId, paranoiaLevel, showToast, t])

  const filteredRules = rules.filter((r) => {
    if (categoryFilter && r.category !== categoryFilter) return false
    if (r.paranoiaLevel > paranoiaLevel) return false
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      const inPattern = r.pattern.toLowerCase().includes(q)
      const inDesc = r.description.toLowerCase().includes(q)
      if (!inPattern && !inDesc) return false
    }
    return true
  })

  if (loading && rules.length === 0) {
    return (
      <div className="tab-panel" id="tab-rulebrowser">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--dim)' }}>
          {t('topbar.loading')}
        </div>
      </div>
    )
  }

  if (error && rules.length === 0) {
    return (
      <div className="tab-panel" id="tab-rulebrowser">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--red)' }}>
          {t('common.networkError')}: {error}
        </div>
      </div>
    )
  }

  return (
    <div className="tab-panel" id="tab-rulebrowser">
      <div className="card" style={{ marginBottom: 20, padding: '12px 20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 14, color: 'var(--accent)' }}>
            {t('phase3.rule_browser.rule_count', { count: filteredRules.length })}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <label style={{ fontSize: 12, color: 'var(--dim)', letterSpacing: '1px', textTransform: 'uppercase' }}>
              {t('phase3.rule_browser.paranoia_level')}
            </label>
            <select
              value={paranoiaLevel}
              onChange={(e) => setParanoiaLevel(Number(e.target.value))}
              style={{
                background: 'rgba(0, 100, 180, 0.15)',
                border: '1px solid var(--border)',
                borderRadius: 4,
                padding: '4px 10px',
                color: 'var(--text)',
                fontSize: 13,
                outline: 'none',
                cursor: 'pointer',
              }}
            >
              <option value={1}>1</option>
              <option value={2}>2</option>
              <option value={3}>3</option>
              <option value={4}>4</option>
            </select>
            <button
              onClick={handleSaveParanoiaLevel}
              disabled={savingLevel}
              style={{
                background: 'rgba(0, 200, 255, 0.1)',
                border: '1px solid var(--accent)',
                borderRadius: 4,
                padding: '5px 14px',
                color: 'var(--accent)',
                fontFamily: "'Rajdhani', sans-serif",
                fontSize: 12,
                fontWeight: 700,
                cursor: 'pointer',
                letterSpacing: '1px',
              }}
            >
              {t('phase3.rule_browser.save_level')}
            </button>
          </div>
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: 20 }}>
        <Card title={t('phase3.rule_browser.search')}>
          <div style={{ display: 'flex', gap: 10 }}>
            <input
              type="text"
              placeholder={t('phase3.rule_browser.search_placeholder')}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                flex: 1,
                background: 'rgba(0, 100, 180, 0.1)',
                border: '1px solid var(--border)',
                borderRadius: 4,
                padding: '7px 12px',
                color: 'var(--text)',
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: 13,
                outline: 'none',
              }}
            />
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as RuleCategory | '')}
              style={{
                background: 'rgba(0, 100, 180, 0.15)',
                border: '1px solid var(--border)',
                borderRadius: 4,
                padding: '7px 10px',
                color: 'var(--text)',
                fontSize: 13,
                outline: 'none',
                cursor: 'pointer',
                minWidth: 140,
              }}
            >
              <option value="">{t('phase3.rule_browser.all_categories')}</option>
              {CATEGORY_LIST.map((cat) => (
                <option key={cat} value={cat}>
                  {t(`phase3.rule_browser.categories.${cat}`)}
                </option>
              ))}
            </select>
          </div>
        </Card>

        <Card title={t('phase3.rule_browser.custom_rule')}>
          <button
            className="st-btn-add"
            onClick={() => setShowCustomRule(!showCustomRule)}
          >
            {showCustomRule ? t('logDetail.title') : t('phase3.rule_browser.add_rule')}
          </button>
        </Card>
      </div>

      {showCustomRule && (
        <Card title={t('phase3.rule_browser.add_rule')} style={{ marginBottom: 20 }}>
          <div className="st-group" style={{ borderBottom: 'none', marginBottom: 0, paddingBottom: 0 }}>
            <div className="st-proxy-row">
              <input
                type="text"
                placeholder={t('phase3.rule_browser.rule_pattern')}
                value={newPattern}
                onChange={(e) => setNewPattern(e.target.value)}
                style={{
                  flex: 1,
                  background: 'rgba(0, 100, 180, 0.1)',
                  border: '1px solid var(--border)',
                  borderRadius: 4,
                  padding: '7px 12px',
                  color: 'var(--text)',
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 13,
                  outline: 'none',
                }}
              />
              <select
                value={newCategory}
                onChange={(e) => setNewCategory(e.target.value as RuleCategory)}
                style={{
                  background: 'rgba(0, 100, 180, 0.15)',
                  border: '1px solid var(--border)',
                  borderRadius: 4,
                  padding: '7px 10px',
                  color: 'var(--text)',
                  fontSize: 13,
                  outline: 'none',
                }}
              >
                {CATEGORY_LIST.map((cat) => (
                  <option key={cat} value={cat}>
                    {t(`phase3.rule_browser.categories.${cat}`)}
                  </option>
                ))}
              </select>
              <select
                value={newSeverity}
                onChange={(e) => setNewSeverity(e.target.value as RuleSeverity)}
                style={{
                  background: 'rgba(0, 100, 180, 0.15)',
                  border: '1px solid var(--border)',
                  borderRadius: 4,
                  padding: '7px 10px',
                  color: 'var(--text)',
                  fontSize: 13,
                  outline: 'none',
                }}
              >
                <option value="low">{t('common.low')}</option>
                <option value="medium">{t('common.medium')}</option>
                <option value="high">{t('common.high')}</option>
                <option value="critical">{t('common.critical')}</option>
              </select>
            </div>
            <div className="st-proxy-row">
              <input
                type="text"
                placeholder={t('phase3.rule_browser.rule_description')}
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
                style={{
                  flex: 1,
                  background: 'rgba(0, 100, 180, 0.1)',
                  border: '1px solid var(--border)',
                  borderRadius: 4,
                  padding: '7px 12px',
                  color: 'var(--text)',
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 13,
                  outline: 'none',
                }}
              />
              <input
                type="text"
                placeholder={t('phase3.rule_browser.mitre_id')}
                value={newMitreId}
                onChange={(e) => setNewMitreId(e.target.value)}
                style={{
                  width: 160,
                  background: 'rgba(0, 100, 180, 0.1)',
                  border: '1px solid var(--border)',
                  borderRadius: 4,
                  padding: '7px 12px',
                  color: 'var(--text)',
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 13,
                  outline: 'none',
                }}
              />
              <button
                onClick={handleCreateRule}
                style={{
                  background: 'var(--accent)',
                  color: '#000',
                  border: 'none',
                  padding: '8px 20px',
                  borderRadius: 4,
                  fontWeight: 700,
                  cursor: 'pointer',
                  fontFamily: "'Rajdhani', sans-serif",
                  letterSpacing: '1.5px',
                  textTransform: 'uppercase',
                  fontSize: 12,
                }}
              >
                {t('phase3.rule_browser.create_rule')}
              </button>
            </div>
          </div>
        </Card>
      )}

      <Card title={t('phase3.rule_browser.title')}>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>ID</th>
                <th>{t('phase3.rule_browser.category')}</th>
                <th>{t('phase3.rule_browser.severity')}</th>
                <th>{t('phase3.rule_browser.description')}</th>
                <th>{t('phase3.rule_browser.mitre_id')}</th>
                <th>{t('phase3.rule_browser.enabled')}</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.length > 0 ? (
                filteredRules.map((rule) => (
                  <tr key={rule.id}>
                    <td style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 12 }}>
                      {rule.id}
                    </td>
                    <td>
                      <span style={{ fontSize: 12 }}>
                        {t(`phase3.rule_browser.categories.${rule.category}`)}
                      </span>
                    </td>
                    <td>
                      <Badge variant={SEVERITY_COLORS[rule.severity]}>
                        {t(`common.${rule.severity}`)}
                      </Badge>
                    </td>
                    <td style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 13 }}>
                      {rule.description}
                    </td>
                    <td style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: 'var(--dim)' }}>
                      {rule.mitreId || '-'}
                    </td>
                    <td>
                      <label style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
                        <input
                          type="checkbox"
                          checked={rule.enabled}
                          onChange={() => handleToggleRule(rule)}
                          style={{ accentColor: 'var(--accent)', width: 16, height: 16 }}
                        />
                      </label>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} style={{ color: 'var(--dim)', textAlign: 'center', padding: '20px 0' }}>
                    {t('dashboard.noData')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

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
