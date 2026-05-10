export type TabId = 'globe' | 'dashboard' | 'logs' | 'ipmanage' | 'system' | 'settings' | 'plugins' | 'behavior_monitor' | 'cluster_manager' | 'api_key_manager';

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
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
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

export type ReputationProvider = 'abuseipdb' | 'greynoise' | 'virustotal' | 'spamhaus' | 'ipinfo';

export interface ProviderConfig {
  id: ReputationProvider;
  name: string;
  enabled: boolean;
  apiKey: string;
}

export interface IpReputationResult {
  ip: string;
  score: number;
  riskLevel: 'clean' | 'low' | 'medium' | 'high';
  reports?: number;
  sources?: string[];
  details?: string;
}

export interface CacheStats {
  cacheSize: number;
  hitRate: number;
  cleanCount: number;
  flaggedCount: number;
}

export type RuleSeverity = 'low' | 'medium' | 'high' | 'critical';

export type RuleCategory =
  | 'sqli'
  | 'xss'
  | 'rce'
  | 'lfi'
  | 'rfi'
  | 'ssrf'
  | 'bot'
  | 'bruteforce'
  | 'ddos'
  | 'upload'
  | 'scan'
  | 'custom';

export interface Rule {
  id: string;
  category: RuleCategory;
  severity: RuleSeverity;
  pattern: string;
  description: string;
  mitreId?: string;
  paranoiaLevel: number;
  enabled: boolean;
}

export interface PatchSuggestion {
  id: string;
  vulnerability: string;
  rootCause: string;
  fix: string;
  codeExample?: string;
  prevention: string;
  status: 'reviewed' | 'applied' | 'ignored';
}

export interface BehaviorScore {
  ip: string;
  score: number;
  velocity: number;
  diversity: number;
  error_rate: number;
  request_count: number;
  first_seen: string;
  last_seen: string;
  trend: 'stable' | 'increasing' | 'decreasing';
}

export interface BehaviorProfile {
  ip: string;
  scores: BehaviorScore[];
  overall_risk: 'low' | 'medium' | 'high' | 'critical';
  profile_created: string;
}

export interface UseLogsReturn {
  allLogs: Log[]
  searchLogs: Log[]
  searchMode: boolean
  searchQuery: string
  page: number
  totalPages: number
  loading: boolean
  noMoreData: boolean
  loadedDates: string[]
  currentDate: string
  selectedLog: Log | null
  modalOpen: boolean
  rrwebLoading: boolean
  rrwebEvents: unknown[]
  hasReplayData: boolean
  setSearchQuery: (q: string) => void
  handleSearch: () => Promise<void>
  handleClearSearch: () => void
  handlePrevDay: () => void
  handleNextDay: () => void
  handleGoPage: (p: number) => void
  openDetail: (log: Log) => void
  closeDetail: () => void
}

export interface ReputationConfig {
  provider: ReputationProvider
  api_key: string
  enabled: boolean
}

export type ClusterRole = 'primary' | 'secondary';

export interface ClusterNode {
  id: string;
  name: string;
  role: ClusterRole;
  url: string;
  status: 'online' | 'offline' | 'degraded';
  last_heartbeat: string;
  synced: boolean;
}

export interface WafApiKey {
  id: string;
  key: string;
  name: string;
  permissions: string[];
  rate_limit: number;
  created_at: string;
  expires_at?: string;
  usage_count: number;
}

export type PatchStatus = 'pending' | 'reviewed' | 'applied' | 'ignored';

export interface PatchVulnerability {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: PatchStatus;
  description: string;
  root_cause: string;
  fix_recommendation: string;
  code_example: string;
  prevention_tips: string[];
  created_at: string;
  applied_at?: string;
}

export type WafEventSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface WafEvent {
  id: string;
  timestamp: string;
  severity: WafEventSeverity;
  event_type: string;
  source_ip: string;
  target_url: string;
  rule_id?: string;
  action: 'blocked' | 'logged' | 'challenged' | 'allowed';
  details: Record<string, unknown>;
}

export interface Phase3Settings {
  rule_engine: {
    paranoia_level: number;
    rule_paths: string[];
    crs_auto_update: boolean;
  };
  ip_reputation: {
    providers: { provider: ReputationProvider; api_key: string; enabled: boolean }[];
  };
  llm_tier: {
    quick_model: string;
    quick_url: string;
    quick_key: string;
    deep_model: string;
    deep_url: string;
    deep_key: string;
  };
  behavior_profiling: {
    enabled: boolean;
    window_seconds: number;
  };
  cluster: {
    enabled: boolean;
    role: ClusterRole;
    redis_url: string;
  };
  waf_api: {
    enabled: boolean;
  };
  auto_patch: {
    enabled: boolean;
  };
}

export interface Phase3SettingsResponse {
  status: 'success' | 'error';
  data?: Phase3Settings;
  msg?: string;
}

export interface BehaviorScoreEntry {
  ip: string;
  score: number;
  requests_per_min: number;
  unique_paths: number;
  error_rate: number;
  status: 'normal' | 'monitor' | 'challenge' | 'block';
  trend?: number[];
}

export interface SuspiciousIP {
  ip: string;
  score: number;
  reason: string;
}

export interface BehaviorMonitorData {
  scores: BehaviorScoreEntry[];
  suspicious_ips: SuspiciousIP[];
}

export type NodeRole = 'primary' | 'secondary';
export type NodeStatus = 'online' | 'offline';

export interface ClusterNodeExternal {
  node_id: string;
  role: NodeRole;
  ip: string;
  status: NodeStatus;
  last_heartbeat: string;
  uptime: string;
}

export interface NodeSyncStatus {
  node_id: string;
  pending_updates: number;
  acked_updates: number;
  sync_status: 'synced' | 'pending' | 'error';
}

export interface ClusterEvent {
  timestamp: string;
  event_type: string;
  node_id: string;
  message: string;
}

export interface ClusterData {
  nodes: ClusterNodeExternal[];
  sync_status: NodeSyncStatus[];
  recent_events: ClusterEvent[];
  pending_updates: number;
}

export type ApiKeyPermission = 'read' | 'write' | 'block' | 'stats' | 'events';

export interface ApiKeyEntry {
  id: string;
  name: string;
  key: string;
  permissions: ApiKeyPermission[];
  rate_limit: number;
  created_at: string;
  is_revoked: boolean;
}

export interface GenerateApiKeyRequest {
  name: string;
  permissions: ApiKeyPermission[];
  rate_limit: number;
}

export interface GenerateApiKeyResponse {
  key: string;
  entry: ApiKeyEntry;
}
