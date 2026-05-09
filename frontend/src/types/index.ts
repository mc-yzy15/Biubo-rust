export type TabId = 'globe' | 'dashboard' | 'logs' | 'ipmanage' | 'system' | 'settings';

export interface NavItem {
  id: TabId;
  icon: React.ReactNode;
  labelKey: string;
}

export interface HostInfo {
  host: string;
  port: number;
}

export interface AppState {
  currentTab: TabId;
  hosts: HostInfo[];
  currentHost: string | null;
  language: string;
}

export interface AppContextType extends AppState {
  setTab: (tab: TabId) => void;
  setHosts: (hosts: HostInfo[]) => void;
  setCurrentHost: (host: string) => void;
  setLanguage: (lang: string) => void;
}

export interface SiteInfo {
  domain?: string;
  status?: string;
  description?: string;
  created_at?: string;
}

export interface EngagementData {
  total?: number;
  bounce_rate?: number;
  avg_session_duration?: number;
}

export interface SourceData {
  direct?: number;
  search?: number;
  social?: number;
  referral?: number;
}

export interface VisitorData {
  total?: number;
  unique?: string[];
}

export interface TrafficData {
  visitors?: VisitorData;
  engagement?: EngagementData;
  sources?: SourceData;
}

export interface SecurityData {
  blocked_requests?: number;
  block_rate?: number;
  attack_types?: Record<string, number>;
  top_attack_ips?: Record<string, number> | Array<[string, number]>;
  top_target_urls?: Record<string, number> | Array<[string, number]>;
  geo?: {
    attackers_by_country?: Record<string, number>;
    visitors_by_country?: Record<string, number>;
  };
}

export interface ClientData {
  devices?: Record<string, number>;
  browsers?: Record<string, number>;
  os?: Record<string, number>;
}

export interface AnalyticsData {
  traffic?: TrafficData;
  security?: SecurityData;
  clients?: ClientData;
  trending_urls?: Record<string, number>;
}

export interface WafInfoResponse {
  site?: SiteInfo;
  analytics?: AnalyticsData;
}

export interface ProxySite {
  domain: string;
  backend: string;
}

export interface SettingsConfig {
  DASHBOARD_PASSWORD: string;
  API_KEY: string;
  LLM_MODEL: string;
  LLM_BASE_URL: string;
  PROXY_MAP: Record<string, string>;
}

export interface SettingsConfigResponse {
  status: 'success' | 'error';
  data?: SettingsConfig;
  msg?: string;
}

export interface Log {
  timestamp?: number;
  time?: string;
  ip?: string;
  country?: string;
  city?: string;
  method?: string;
  path?: string;
  url?: string;
  status?: number | string;
  type?: string;
  attack_types?: string[];
  request_id?: string;
  _date?: string;
  rrweb?: unknown;
  [key: string]: unknown;
}

export interface UseLogsReturn {
  allLogs: Log[];
  searchLogs: Log[];
  searchMode: boolean;
  searchQuery: string;
  page: number;
  totalPages: number;
  loading: boolean;
  noMoreData: boolean;
  loadedDates: string[];
  currentDate: string;
  selectedLog: Log | null;
  modalOpen: boolean;
  rrwebLoading: boolean;
  rrwebEvents: unknown[];
  hasReplayData: boolean;
  setSearchQuery: (q: string) => void;
  handleSearch: () => Promise<void>;
  handleClearSearch: () => void;
  handlePrevDay: () => void;
  handleNextDay: () => void;
  handleGoPage: (p: number) => void;
  openDetail: (log: Log) => void;
  closeDetail: () => void;
}
