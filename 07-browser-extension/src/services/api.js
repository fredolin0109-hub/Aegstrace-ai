/**
 * AEGISTRACE Extension API Service
 * Communicates with FastAPI backend at http://127.0.0.1:8000
 * Includes fallback heuristics if backend is momentarily offline.
 */

export const BACKEND_URL = 'http://127.0.0.1:8000';

class ExtensionApiService {
  constructor(baseUrl = BACKEND_URL) {
    this.baseUrl = baseUrl;
  }

  async checkHealth() {
    try {
      const res = await fetch(`${this.baseUrl}/api/health`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });
      if (!res.ok) throw new Error(`Status ${res.status}`);
      return await res.json();
    } catch (err) {
      return { status: 'offline', error: err.message };
    }
  }

  async analyzeUrl(url, options = {}) {
    const payload = {
      url: url,
      client_ip: options.client_ip || null,
      user_agent: options.user_agent || navigator.userAgent,
      redirect_chain: options.redirect_chain || null,
    };

    try {
      const res = await fetch(`${this.baseUrl}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Analysis failed (${res.status})`);
      }

      return await res.json();
    } catch (err) {
      // Graceful local heuristic fallback
      return this.localHeuristicFallback(url, err.message);
    }
  }

  async investigateUrl(url, options = {}) {
    const payload = {
      url: url,
      depth: options.depth || 'standard',
      force_escalate: options.force_escalate || false,
      client_ip: options.client_ip || null,
      user_agent: options.user_agent || navigator.userAgent,
      domain_age_days: options.domain_age_days || null,
    };

    const res = await fetch(`${this.baseUrl}/api/investigate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Investigation failed (${res.status})`);
    }

    return await res.json();
  }

  async triggerUiPathAction(incidentId, actionType, parameters = {}) {
    const payload = {
      incident_id: incidentId,
      action_type: actionType,
      parameters: parameters,
    };

    const res = await fetch(`${this.baseUrl}/api/uipath/trigger`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `UiPath trigger failed (${res.status})`);
    }

    return await res.json();
  }

  async getUiPathStatus(executionId) {
    const res = await fetch(`${this.baseUrl}/api/uipath/status/${executionId}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });

    if (!res.ok) {
      throw new Error(`UiPath status check failed (${res.status})`);
    }

    return await res.json();
  }

  async sendRiskAlert(data) {
    const payload = {
      url: data.url,
      risk_score: Math.min(100, Math.max(0, Math.round(data.risk_score <= 1.0 ? data.risk_score * 100 : data.risk_score))),
      classification: data.classification || 'HIGH_RISK',
      reasons: Array.isArray(data.reasons) ? data.reasons : [data.reasons || 'High threat score detected by extension'],
      incident_id: data.incident_id || null,
    };

    try {
      const res = await fetch(`${this.baseUrl}/api/risk-alert`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Risk alert dispatch failed (${res.status})`);
      }

      return await res.json();
    } catch (err) {
      console.warn('[AEGISTRACE EXT] sendRiskAlert fallback:', err.message);
      return {
        success: true,
        risk_level: payload.risk_score >= 70 ? 'HIGH' : (payload.risk_score >= 30 ? 'MEDIUM' : 'LOW'),
        incident_id: payload.incident_id || `INC-${Date.now().toString().slice(-6)}`,
        uipath_status: 'TRIGGERED (OFFLINE_SIM)',
        email_status: 'TEST_MODE_LOGGED',
        execution_id: `UIPATH-EXT-${Date.now().toString(16).toUpperCase()}`,
        message: 'Alert generated via local extension engine fallback',
        offline_fallback: true,
      };
    }
  }

  localHeuristicFallback(rawUrl, reason) {
    let hostname = '';
    try {
      hostname = new URL(rawUrl).hostname.toLowerCase();
    } catch {
      hostname = rawUrl.toLowerCase();
    }

    const suspiciousKeywords = [
      'login', 'verify', 'update', 'secure', 'account', 'banking',
      'signin', 'paypal', 'apple', 'microsoft', 'recover', 'wallet'
    ];
    const suspiciousTlds = ['.xyz', '.top', '.buzz', '.cn', '.ru', '.cfd', '.sbs', '.cc'];

    let score = 0.05;
    const explanations = [];

    const foundKw = suspiciousKeywords.filter(k => hostname.includes(k));
    if (foundKw.length > 0) {
      score += 0.25 * foundKw.length;
      explanations.push(`Contains credential-harvesting tokens: ${foundKw.join(', ')}`);
    }

    if (suspiciousTlds.some(t => hostname.endsWith(t))) {
      score += 0.35;
      explanations.push('High-risk top-level domain extension observed');
    }

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      score += 0.50;
      explanations.push('Direct raw IPv4 address navigation detected');
    }

    const normalizedScore = Math.min(0.99, Math.max(0.01, score));
    let classification = 'SAFE';
    let recommendation = 'ALLOW';

    if (normalizedScore >= 0.70) {
      classification = 'HIGH_RISK';
      recommendation = 'BLOCK';
    } else if (normalizedScore >= 0.35) {
      classification = 'SUSPICIOUS';
      recommendation = 'WARN';
    }

    return {
      id: 0,
      url: rawUrl,
      normalized_url: rawUrl,
      domain: hostname,
      risk_score: normalizedScore,
      classification: classification,
      confidence: 0.65,
      recommendation: recommendation,
      indicators: explanations.map(exp => ({
        indicator_type: 'LOCAL_HEURISTIC',
        value: hostname,
        severity: classification === 'HIGH_RISK' ? 'HIGH' : 'MEDIUM',
        details: { note: exp },
      })),
      ml_risk_score: normalizedScore,
      ml_classification: classification,
      ml_confidence: 0.65,
      ml_explanations: explanations,
      dsa_verdict: classification,
      dsa_risk_score: normalizedScore,
      created_at: new Date().toISOString(),
      offline_fallback: true,
      offline_reason: reason,
    };
  }
}

export const api = new ExtensionApiService();
export default api;
