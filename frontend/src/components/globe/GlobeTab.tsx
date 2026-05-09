import { useContext } from 'react'
import { AppContext } from '../../context/AppContext'
import { useGlobeData } from '../../hooks/useGlobeData'
import { GlobeView } from './GlobeView'
import { ThreatStats } from './ThreatStats'
import { AttackTypeBars } from './AttackTypeBars'
import { CountryList } from './CountryList'
import { ThreatLevel } from './ThreatLevel'
import { TimeRangePicker } from './TimeRangePicker'
import { IPSearch } from './IPSearch'
import { GlobeControls } from './GlobeControls'

export function GlobeTab() {
  const ctx = useContext(AppContext)
  const currentHost = ctx?.currentHost ?? null

  const {
    attackData,
    serverNode,
    stats,
    typeCounts,
    countryCounts,
    ipSearchResults,
    ipSearchLoading,
    autoRotate,
    paused,
    speed,
    setAutoRotate,
    setPaused,
    setSpeed,
    clearAll,
    searchIP,
    globeRef,
    pushAttack,
    getGeo,
    logToAttack,
    serverNodeRef,
  } = useGlobeData(currentHost)

  const handleReload = () => {
    clearAll()
  }

  const handleHighlightIP = (lat: number, lng: number, _type: string) => {
    if (!globeRef.current) return
    globeRef.current.pointOfView({ lat, lng, altitude: 1.5 }, 1000)
  }

  return (
    <div className="tab-panel" id="tab-globe">
      <div className="globe-wrap">
        <GlobeView
          attackData={attackData}
          serverNode={serverNode}
          autoRotate={autoRotate}
          speed={speed}
          paused={paused}
          globeRef={globeRef}
          pushAttack={pushAttack}
          getGeo={getGeo}
          logToAttack={logToAttack}
        />

        <div className="g-panel-left">
          <ThreatStats
            total={stats.total}
            ratePerMin={stats.ratePerMin}
            blocked={stats.blocked}
            critical={stats.critical}
          />
          <AttackTypeBars typeCounts={typeCounts} />
        </div>

        <div className="g-panel-right">
          <CountryList countryCounts={countryCounts} />
          <ThreatLevel total={stats.total} />
          <TimeRangePicker onReload={handleReload} />
          <IPSearch
            onSearch={searchIP}
            results={ipSearchResults}
            loading={ipSearchLoading}
            onHighlight={handleHighlightIP}
            getGeo={getGeo}
            logToAttack={logToAttack}
            pushAttack={pushAttack}
            serverNode={serverNodeRef}
          />
        </div>

        <GlobeControls
          autoRotate={autoRotate}
          paused={paused}
          speed={speed}
          onToggleRotate={() => setAutoRotate(!autoRotate)}
          onTogglePause={() => setPaused(!paused)}
          onSpeedChange={setSpeed}
          onClear={clearAll}
        />
      </div>
    </div>
  )
}
