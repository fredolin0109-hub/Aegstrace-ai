import {
  ScanRequest,
  ScanResponse,
  InvestigateRequest,
  InvestigateResponse,
  DashboardStatsResponse,
  IncidentCreate,
  IncidentUpdate,
  IncidentResponse,
  IncidentListResponse,
  UiPathTriggerRequest,
  UiPathActionResponse,
  UiPathStatusResponse,
  ThreatIntelLookupResponse,
  ThreatIntelStatsResponse,
  HealthResponse,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

class ApiService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = API_BASE_URL;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
    
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...options.headers,
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (!response.ok) {
        let errorMsg = `HTTP Error ${response.status} ${response.statusText}`;
        try {
          const errJson = await response.json();
          if (errJson.detail) {
            errorMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
          } else if (errJson.message) {
            errorMsg = errJson.message;
          }
        } catch {
          // ignore non-json response
        }
        throw new Error(errorMsg);
      }

      return (await response.json()) as T;
    } catch (err: any) {
      // If fetching directly failed (e.g. CORS or backend not yet listening on 8000), try proxy fallback if on same host
      if (err.message && err.message.includes('Failed to fetch') && !endpoint.startsWith('/api')) {
        console.warn(`Direct call to ${url} failed; trying relative endpoint`);
      }
      throw err;
    }
  }

  // Health
  async checkHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/api/health');
  }

  // Analysis & Investigation
  async analyzeUrl(payload: ScanRequest): Promise<ScanResponse> {
    return this.request<ScanResponse>('/api/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async investigateUrl(payload: InvestigateRequest): Promise<InvestigateResponse> {
    return this.request<InvestigateResponse>('/api/investigate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // Dashboard Stats
  async getDashboardStats(): Promise<DashboardStatsResponse> {
    return this.request<DashboardStatsResponse>('/api/dashboard/stats');
  }

  // Incidents
  async getIncidents(params?: {
    status?: string;
    severity?: string;
    search?: string;
    sort_by?: string;
    skip?: number;
    limit?: number;
  }): Promise<IncidentListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.status && params.status !== 'ALL') searchParams.append('status', params.status);
    if (params?.severity && params.severity !== 'ALL') searchParams.append('severity', params.severity);
    if (params?.search) searchParams.append('search', params.search);
    if (params?.sort_by) searchParams.append('sort_by', params.sort_by);
    if (params?.skip !== undefined) searchParams.append('skip', params.skip.toString());
    if (params?.limit !== undefined) searchParams.append('limit', params.limit.toString());

    const queryString = searchParams.toString();
    const endpoint = `/api/incidents${queryString ? `?${queryString}` : ''}`;
    return this.request<IncidentListResponse>(endpoint);
  }

  async getTriagedIncidents(status = 'OPEN', limit = 20): Promise<IncidentListResponse> {
    const searchParams = new URLSearchParams({
      status,
      limit: limit.toString(),
    });
    return this.request<IncidentListResponse>(`/api/incidents/triage?${searchParams.toString()}`);
  }

  async getIncidentById(incidentId: number): Promise<IncidentResponse> {
    return this.request<IncidentResponse>(`/api/incidents/${incidentId}`);
  }

  async createIncident(payload: IncidentCreate): Promise<IncidentResponse> {
    return this.request<IncidentResponse>('/api/incidents', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async updateIncident(incidentId: number, payload: IncidentUpdate): Promise<IncidentResponse> {
    return this.request<IncidentResponse>(`/api/incidents/${incidentId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  }

  // UiPath RPA Actions
  async triggerUiPathAction(payload: UiPathTriggerRequest): Promise<UiPathActionResponse> {
    return this.request<UiPathActionResponse>('/api/uipath/trigger', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getUiPathStatus(executionId: string): Promise<UiPathStatusResponse> {
    return this.request<UiPathStatusResponse>(`/api/uipath/status/${executionId}`);
  }

  async triggerRiskAlert(payload: {
    url: string;
    risk_score: number;
    classification: string;
    reasons: string[];
    incident_id?: string;
  }): Promise<any> {
    return this.request('/api/risk-alert', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async retryAutomation(incidentId: string, retryType: 'UIPATH' | 'EMAIL' | 'ALL' = 'ALL'): Promise<any> {
    return this.request('/api/uipath/retry', {
      method: 'POST',
      body: JSON.stringify({ incident_id: incidentId, retry_type: retryType }),
    });
  }

  async sendUiPathCallback(payload: {
    incident_id: string;
    execution_id: string;
    status: string;
    email_status?: string;
    timestamp?: string;
    details?: Record<string, any>;
  }): Promise<any> {
    return this.request('/api/uipath/callback', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // Threat Intelligence
  async lookupThreatIntel(target: string, targetType?: string, refresh = false): Promise<ThreatIntelLookupResponse> {
    const searchParams = new URLSearchParams({
      target,
      refresh: refresh ? 'true' : 'false',
    });
    if (targetType) {
      searchParams.append('target_type', targetType);
    }
    return this.request<ThreatIntelLookupResponse>(`/api/threat-intel/lookup?${searchParams.toString()}`);
  }

  async getThreatIntelStats(): Promise<ThreatIntelStatsResponse> {
    return this.request<ThreatIntelStatsResponse>('/api/threat-intel/stats');
  }

  async clearThreatIntelCache(): Promise<{ message: string }> {
    return this.request<{ message: string }>('/api/threat-intel/clear-cache', {
      method: 'POST',
    });
  }
}

export const api = new ApiService();
export default api;
