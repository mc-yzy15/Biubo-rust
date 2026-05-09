import { useApp } from './context/AppContext'
import { AppLayout } from './components/layout/AppLayout'
import { DashboardTab } from './components/dashboard'
import { GlobeTab } from './components/globe'
import { LogsTab } from './components/logs'
import { IPManagerTab } from './components/ipmanager'
import { SystemTab } from './components/system'
import { SettingsTab } from './components/settings'
import './styles/global.css'

const TAB_COMPONENTS: Record<string, React.ComponentType> = {
  globe: GlobeTab,
  dashboard: DashboardTab,
  logs: LogsTab,
  ipmanage: IPManagerTab,
  system: SystemTab,
  settings: SettingsTab,
}

function App() {
  const { currentTab } = useApp()
  const TabContent = TAB_COMPONENTS[currentTab] || DashboardTab

  return (
    <AppLayout>
      <TabContent />
    </AppLayout>
  )
}

export default App
