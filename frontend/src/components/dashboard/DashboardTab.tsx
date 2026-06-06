import React, { useContext } from 'react'
import { useTranslation } from 'react-i18next'
import { AppContext } from '../../context/AppContext'
import { useDashboard } from '../../hooks/useDashboard'
import { Card } from '../ui/Card'
import { StatCard } from '../ui/StatCard'
import { TypeBar } from '../ui/TypeBar'

export function DashboardTab() {
  const { t } = useTranslation()
  const ctx = useContext(AppContext)
  const currentHost = ctx?.currentHost ?? null
  const { data, loading, error } = useDashboard(currentHost)

  if (loading) {
    return (
      <div className="tab-panel" id="tab-dashboard">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--dim)' }}>
          {t('topbar.loading')}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="tab-panel" id="tab-dashboard">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--red)' }}>
          {t('common.networkError')}: {error}
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="tab-panel" id="tab-dashboard">
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--dim)' }}>
          {t('dashboard.noData')}
        </div>
      </div>
    )
  }

  return (
    <div className="tab-panel" id="tab-dashboard">
      {/* Row 1: 4 key stats */}
      <div className="grid-4" style={{ marginBottom: 20 }}>
        <StatCard variant="blue" label={t('dashboard.totalRequests')} value={data.totalRequests.toLocaleString()} />
        <StatCard variant="red" label={t('dashboard.blockedAttacks')} value={data.blockedAttacks.toLocaleString()} />
        <StatCard variant="green" label={t('dashboard.uniqueVisitors')} value={data.uniqueVisitors.toLocaleString()} />
        <StatCard variant="yellow" label={t('dashboard.blockRate')} value={data.blockRate} />
      </div>

      {/* Row 2: engagement + sources */}
      <div className="grid-2" style={{ marginBottom: 20 }}>
        <Card title={t('dashboard.trafficEngagement')}>
          <div className="detail-row">
            <div className="detail-key">{t('dashboard.totalSessions')}</div>
            <div className="detail-val">{data.engagement.totalSessions.toLocaleString()}</div>
          </div>
          <div className="detail-row">
            <div className="detail-key">{t('dashboard.bounceRate')}</div>
            <div className="detail-val">{data.engagement.bounceRate}</div>
          </div>
          <div className="detail-row">
            <div className="detail-key">{t('dashboard.avgSessionDuration')}</div>
            <div className="detail-val">{data.engagement.avgSessionDuration}</div>
          </div>
        </Card>
        <Card title={t('dashboard.trafficSources')}>
          <TypeBar items={data.sources.map(s => ({ ...s, label: t(`dashboard.${s.label}`) }))} />
        </Card>
      </div>

      {/* Row 3: attack types + devices */}
      <div className="grid-2" style={{ marginBottom: 20 }}>
        <Card title={t('dashboard.attackTypeDist')}>
          {data.attackTypes.length > 0 ? (
            <TypeBar items={data.attackTypes} />
          ) : (
            <div style={{ color: 'var(--dim)', fontSize: 12 }}>{t('dashboard.noData')}</div>
          )}
        </Card>
        <Card title={t('dashboard.deviceBrowserOS')}>
          <div style={{ fontSize: 9, letterSpacing: '1.5px', color: 'var(--dim)', textTransform: 'uppercase', marginBottom: 6 }}>
            {t('dashboard.device')}
          </div>
          {data.devices.length > 0 ? (
            <TypeBar items={data.devices} />
          ) : (
            <div style={{ color: 'var(--dim)', fontSize: 11, marginBottom: 6 }}>{t('dashboard.noData')}</div>
          )}
          <div style={{ fontSize: 9, letterSpacing: '1.5px', color: 'var(--dim)', textTransform: 'uppercase', margin: '10px 0 6px' }}>
            {t('dashboard.browser')}
          </div>
          {data.browsers.length > 0 ? (
            <TypeBar items={data.browsers} />
          ) : (
            <div style={{ color: 'var(--dim)', fontSize: 11, marginBottom: 6 }}>{t('dashboard.noData')}</div>
          )}
          <div style={{ fontSize: 9, letterSpacing: '1.5px', color: 'var(--dim)', textTransform: 'uppercase', margin: '10px 0 6px' }}>
            {t('dashboard.os')}
          </div>
          {data.osList.length > 0 ? (
            <TypeBar items={data.osList} />
          ) : (
            <div style={{ color: 'var(--dim)', fontSize: 11, marginBottom: 6 }}>{t('dashboard.noData')}</div>
          )}
        </Card>
      </div>

      {/* Row 4: top IPs + top URLs */}
      <div className="grid-2" style={{ marginBottom: 20 }}>
        <Card title={t('dashboard.topAttackIPs')}>
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>{t('dashboard.count')}</th>
                </tr>
              </thead>
              <tbody>
                {data.topIPs.length > 0 ? (
                  data.topIPs.map(([ip, cnt], idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: "'Share Tech Mono', monospace" }}>{ip}</td>
                      <td>{cnt}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={2} style={{ color: 'var(--dim)' }}>{t('dashboard.noData')}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title={t('dashboard.topTargetURLs')}>
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>{t('dashboard.count')}</th>
                </tr>
              </thead>
              <tbody>
                {data.topURLs.length > 0 ? (
                  data.topURLs.map(([url, cnt], idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: "'Share Tech Mono', monospace", maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={url}>
                        {url}
                      </td>
                      <td>{cnt}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={2} style={{ color: 'var(--dim)' }}>{t('dashboard.noData')}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      {/* Row 5: trending URLs + attacker geo */}
      <div className="grid-2" style={{ marginBottom: 20 }}>
        <Card title={t('dashboard.trendingURLs')}>
          {data.trendingURLs.length > 0 ? (
            <TypeBar items={data.trendingURLs} maxItems={8} />
          ) : (
            <div style={{ color: 'var(--dim)', fontSize: 12 }}>{t('dashboard.noData')}</div>
          )}
        </Card>
        <Card title={t('dashboard.attackGeo')}>
          {data.attackerGeo.length > 0 ? (
            <TypeBar items={data.attackerGeo} />
          ) : (
            <div style={{ color: 'var(--dim)', fontSize: 12 }}>{t('dashboard.noData')}</div>
          )}
        </Card>
      </div>

      {/* Row 6: visitor geo + site info */}
      <div className="grid-2">
        <Card title={t('dashboard.visitorGeo')}>
          {data.visitorGeo.length > 0 ? (
            <TypeBar items={data.visitorGeo} />
          ) : (
            <div style={{ color: 'var(--dim)', fontSize: 12 }}>{t('dashboard.noData')}</div>
          )}
        </Card>
        <Card title={t('dashboard.wafSiteInfo')}>
          <div className="detail-row">
            <div className="detail-key">{t('dashboard.domain')}</div>
            <div className="detail-val">{data.siteInfo.domain}</div>
          </div>
          <div className="detail-row">
            <div className="detail-key">{t('dashboard.status')}</div>
            <div className="detail-val" style={{ color: data.siteInfo.statusColor as React.CSSProperties['color'] }}>
              {data.siteInfo.status}
            </div>
          </div>
          <div className="detail-row">
            <div className="detail-key">{t('dashboard.description')}</div>
            <div className="detail-val">{data.siteInfo.description}</div>
          </div>
          <div className="detail-row">
            <div className="detail-key">{t('dashboard.createdAt')}</div>
            <div className="detail-val">{data.siteInfo.createdAt}</div>
          </div>
        </Card>
      </div>
    </div>
  )
}
