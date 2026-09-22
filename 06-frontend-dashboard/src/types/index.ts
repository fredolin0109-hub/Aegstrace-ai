/**
 * AEGISTRACE Core Domain Types
 * Mirroring FastAPI backend schemas in 01-backend/app/schemas/
 */

export interface ThreatIndicatorItem {
  indicator_type: string;
  value: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  details: Record<string, any>;
}

export interface ScanRequest {
  url: string;
  client_ip?: string;
  user_agent?: string;
  redirect_chain?: string[];
}

export interface ScanResponse {
  id: number;
  url: string;
  normalized_url: string;
  domain: string;
  ip_address?: string | null;
  risk_score: number;
  classification: 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK' | string;
  confidence: number;
  features: Record<string, any>;
  recommendation: 'ALLOW' | 'WARN' | 'BLOCK' | 'INVESTIGATE' | string;
  indicators: ThreatIndicatorItem[];
  dsa_verdict?: string | null;
  dsa_risk_score?: number | null;
  graph_summary?: {
    total_nodes?: number;
    total_edges?: number;
    has_cycles?: boolean;
    suspicious_redirects_count?: number;
    subdomains_count?: number;
    max_redirect_depth?: number;
    [key: string]: any;
  } | null;
  ml_risk_score?: number | null;
  ml_classification?: string | null;
  ml_confidence?: number | null;
  ml_explanations?: string[] | null;
  threat_intel_score?: number | null;
  threat_intel_verdict?: string | null;
  threat_intel_sources?: string[] | null;
  created_at: string;
}

export interface IncidentCreate {
  url: string;
  title: string;
  description: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  url_scan_id?: number;
  assigned_to?: string;
}

export interface IncidentUpdate {
  title?: string;
  description?: string;
  severity?: string;
  status?: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE' | string;
  assigned_to?: string;
}

export interface UiPathActionSummary {
  id: number;
  action_type: string;
  execution_id: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'SIMULATED' | string;
  executed_at: string;
  completed_at?: string | null;
}

export interface IncidentResponse {
  id: number;
  incident_number: string;
  url_scan_id?: number | null;
  url: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE' | string;
  title: string;
  description: string;
  assigned_to?: string | null;
  resolved_at?: string | null;
  created_at: string;
  updated_at: string;
  uipath_actions: UiPathActionSummary[];
}

export interface IncidentListResponse {
  total: number;
  items: IncidentResponse[];
}

export interface RecentScanItem {
  id: number;
  url: string;
  domain: string;
  risk_score: number;
  classification: string;
  created_at: string;
}

export interface RecentIncidentItem {
  id: number;
  incident_number: string;
  url: string;
  severity: string;
  status: string;
  title: string;
  created_at: string;
}

export interface DashboardStatsResponse {
  total_scans: number;
  safe_urls: number;
  suspicious_urls: number;
  high_risk_urls: number;
  active_incidents: number;
  automated_responses: number;
  severity_breakdown: Record<string, number>;
  status_breakdown: Record<string, number>;
  recent_scans: RecentScanItem[];
  recent_incidents: RecentIncidentItem[];
}

export interface AgentActionTraceItem {
  action_type: string;
  tool_name: string;
  tool_input: Record<string, any>;
  tool_output: Record<string, any>;
  decision_rationale: string;
  status: string;
  timestamp: string;
}

export interface InvestigateRequest {
  url: string;
  url_scan_id?: number;
  depth?: 'standard' | 'deep';
  force_escalate?: boolean;
  client_ip?: string;
  user_agent?: string;
  redirect_chain?: string[];
  domain_age_days?: number;
}

export interface InvestigateResponse {
  url: string;
  url_scan_id?: number | null;
  initial_risk_score: number;
  final_risk_score: number;
  classification: string;
  decision: 'SAFE_PASS' | 'MONITOR' | 'ESCALATE_INCIDENT' | 'TRIGGER_AUTOMATED_RESPONSE' | string;
  incident_created: boolean;
  incident_id?: number | null;
  incident_number?: string | null;
  evidence_collected: string[];
  action_trace: AgentActionTraceItem[];
  recommended_action: string;
  verification_results?: Record<string, any> | null;
}

export interface UiPathTriggerRequest {
  incident_id: number;
  action_type: 'CREATE_TICKET' | 'CONTAIN_HOST' | 'NOTIFY_SOC' | 'ISOLATE_USER' | 'GENERATE_REPORT' | 'BLOCK_DOMAIN' | string;
  parameters?: Record<string, any>;
}

export interface UiPathActionResponse {
  id: number;
  incident_id: number;
  action_type: string;
  execution_id: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'SIMULATED' | string;
  input_payload: Record<string, any>;
  result_payload?: Record<string, any> | null;
  error_message?: string | null;
  executed_at: string;
  completed_at?: string | null;
}

export interface UiPathStatusResponse {
  execution_id: string;
  incident_id: number;
  action_type: string;
  status: string;
  progress_percentage: number;
  executed_at: string;
  completed_at?: string | null;
  result?: Record<string, any> | null;
  error_message?: string | null;
  is_simulation: boolean;
}

export interface ThreatIntelLookupResponse {
  target: string;
  target_type: 'domain' | 'ip' | 'url' | string;
  composite_score: number;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK' | string;
  confidence: number;
  sources_consulted: string[];
  sources_available: string[];
  sources_cached: string[];
  cached: boolean;
  indicators: Array<Record<string, any>>;
  provider_details: Record<string, any>;
  domain_info?: Record<string, any> | null;
  timestamp: string;
}

export interface ThreatIntelStatsResponse {
  cache_stats: {
    entries: number;
    hits: number;
    misses: number;
    hit_ratio: number;
    ttl_seconds: number;
  };
  available_sources: string[];
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  timestamp: string;
  database: string;
  demo_mode: boolean;
  environment: string;
}
