import { useTranslation } from 'react-i18next'

interface CountryListProps {
  countryCounts: Record<string, number>
}

const COUNTRY_FLAGS: Record<string, string> = {
  'US': '\ud83c\uddfa\ud83c\uddf8', 'CN': '\ud83c\udde8\ud83c\uddf3', 'RU': '\ud83c\uddf7\ud83c\uddfa', 'DE': '\ud83c\udde9\ud83c\uddea',
  'GB': '\ud83c\uddec\ud83c\udde7', 'FR': '\ud83c\uddeb\ud83c\uddf7', 'JP': '\ud83c\uddef\ud83c\uddf5', 'KR': '\ud83c\uddf0\ud83c\uddf7',
  'IN': '\ud83c\uddee\ud83c\uddf3', 'BR': '\ud83c\udde7\ud83c\uddf7', 'CA': '\ud83c\udde8\ud83c\udde6', 'AU': '\ud83c\udde6\ud83c\uddfa',
  'NL': '\ud83c\uddf3\ud83c\uddf1', 'IT': '\ud83c\uddee\ud83c\uddf9', 'ES': '\ud83c\uddea\ud83c\uddf8', 'MX': '\ud83c\uddf2\ud83c\uddfd',
  'SE': '\ud83c\uddf8\ud83c\uddea', 'NO': '\ud83c\uddf3\ud83c\uddf4', 'CH': '\ud83c\udde8\ud83c\udded', 'SG': '\ud83c\uddf8\ud83c\uddec',
  'UA': '\ud83c\uddfa\ud83c\udde6', 'PL': '\ud83c\uddf5\ud83c\uddf1', 'TR': '\ud83c\uddf9\ud83c\uddf7', 'ID': '\ud83c\uddee\ud83c\udde9',
  'TH': '\ud83c\uddf9\ud83c\udded', 'VN': '\ud83c\uddfb\ud83c\uddf3', 'PH': '\ud83c\uddf5\ud83c\udded', 'MY': '\ud83c\uddf2\ud83c\uddfe',
}

function getFlagForCountry(name: string): string {
  const code = Object.keys(COUNTRY_FLAGS).find(k =>
    k === name.toUpperCase() || name.toUpperCase().includes(k)
  )
  return code ? COUNTRY_FLAGS[code] : '\ud83c\udf10'
}

export function CountryList({ countryCounts }: CountryListProps) {
  const { t } = useTranslation()

  const sorted = Object.entries(countryCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)

  const maxCount = sorted[0]?.[1] || 1

  return (
    <div className="g-card">
      <div className="g-card-title">{t('globe.sourceCountries')}</div>
      {sorted.length > 0 ? (
        sorted.map(([country, count], i) => {
          const flag = getFlagForCountry(country)
          return (
            <div key={country} className="country-row">
              <div className="country-rank">{i + 1}</div>
              <div style={{ fontSize: 12 }}>{flag}</div>
              <div className="country-name">{country}</div>
              <div className="country-bar-bg">
                <div className="country-bar-fill" style={{ width: `${(count / maxCount) * 100}%` }} />
              </div>
              <div className="country-count">{count}</div>
            </div>
          )
        })
      ) : (
        <div style={{ color: 'var(--dim)', fontSize: 11 }}>{t('globe.waitingForData')}</div>
      )}
    </div>
  )
}
