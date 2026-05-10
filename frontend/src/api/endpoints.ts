export const endpoints = {
  hosts: '/dashboard/hosts',
  stats: '/dashboard/stats',
  logs: '/dashboard/logs',
  whitelist: '/dashboard/whitelist',
  blacklist: '/dashboard/blacklist',
  system: '/dashboard/system',
  settings: '/dashboard/settings',

  patches: '/api/patches',
  patchStatus: (id: string) => `/api/patches/${id}/status`,

  reputation: '/api/reputation',
  reputationLookup: (ip: string) => `/api/reputation/lookup?ip=${ip}`,

  rules: '/api/rules',
  rulesCategories: '/api/rules/categories',

  behavior: '/api/behavior',
  behaviorScores: '/api/behavior/scores',

  cluster: '/api/cluster',

  wafKeys: '/api/waf-keys',

  wafEvents: '/api/events',

  phase3Settings: '/api/phase3/settings',

  clusterHealth: '/api/cluster/health',
  clusterSyncStatus: '/api/cluster/sync-status',
  wafCheck: '/api/waf/v1/check',
  wafReport: '/api/waf/v1/report',
  wafThreat: (ip: string) => `/api/waf/v1/threat/${ip}`,
  wafBlock: '/api/waf/v1/block',
  wafUnblock: '/api/waf/v1/unblock',
  wafStats: '/api/waf/v1/stats',
  ipReputationLookup: (ip: string) => `/api/v1/ip-reputation/${ip}`,
  ipReputationProviders: '/api/v1/ip-reputation/providers',
  ipReputationCacheStats: '/api/v1/ip-reputation/cache-stats',
  rulesList: '/api/v1/rules',
  rulesUpdate: '/api/v1/rules/update',
  rulesCreate: '/api/v1/rules',
};
