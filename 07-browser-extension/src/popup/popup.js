/**
 * AEGISTRACE Extension Popup Controller
 * Manages active tab URL analysis, score gauge animation,
 * autonomous agent investigation escalation, and UiPath RPA triggers.
 */

import { api } from '../services/api.js';

let currentUrl = '';
let currentTabId = null;
let currentIncidentId = null;

// DOM Elements
const healthPill = document.getElementById('backend-health-pill');
const healthText = document.getElementById('health-text');
const targetDomainEl = document.getElementById('target-domain');
const targetUrlEl = document.getElementById('target-url');
const btnCopyUrl = document.getElementById('btn-copy-url');

const gaugeProgress = document.getElementById('gauge-progress');
const riskScoreNum = document.getElementById('risk-score-num');
const classificationBadge = document.getElementById('classification-badge');
const recommendationText = document.getElementById('recommendation-text');

const dsaVerdictPill = document.getElementById('dsa-verdict-pill');
const mlVerdictPill = document.getElementById('ml-verdict-pill');
const intelVerdictPill = document.getElementById('intel-verdict-pill');

const iocCountBadge = document.getElementById('ioc-count-badge');
const findingsList = document.getElementById('findings-list');

const investigationCard = document.getElementById('investigation-card');
const investigationStatus = document.getElementById('investigation-status');
const investigationSteps = document.getElementById('investigation-steps');
const incidentPillBox = document.getElementById('incident-pill-box');
const incidentNumberTag = document.getElementById('incident-number-tag');

const btnReanalyze = document.getElementById('btn-reanalyze');
const btnInvestigate = document.getElementById('btn-investigate');
const btnRpaContain = document.getElementById('btn-rpa-contain');
const btnOpenDashboard = document.getElementById('btn-open-dashboard');

// Update backend health UI
async function checkHealthStatus() {
  try {
    const health = await api.checkHealth();
    if (health && health.status === 'healthy') {
      healthPill.className = 'health-pill online';
      healthText.textContent = 'API: Online (8000)';
    } else {
      healthPill.className = 'health-pill offline';
      healthText.textContent = 'API: Offline (Heuristic)';
    }
  } catch {
    healthPill.className = 'health-pill offline';
    healthText.textContent = 'API: Offline (Heuristic)';
  }
}

// Render circular score gauge
function updateScoreGauge(score, classification) {
  const normalized = Math.min(100, Math.max(0, Math.round(score <= 1.0 ? score * 100 : score)));
  riskScoreNum.textContent = `${normalized}%`;

  const circumference = 364.4; // 2 * PI * 58
  const offset = circumference - (normalized / 100) * circumference;
  gaugeProgress.style.strokeDashoffset = offset;

  if (normalized >= 70 || classification === 'HIGH_RISK') {
    gaugeProgress.style.stroke = '#f43f5e';
    classificationBadge.className = 'verdict-badge high_risk';
    classificationBadge.textContent = 'HIGH RISK';
  } else if (normalized >= 35 || classification === 'SUSPICIOUS') {
    gaugeProgress.style.stroke = '#f59e0b';
    classificationBadge.className = 'verdict-badge suspicious';
    classificationBadge.textContent = 'SUSPICIOUS';
  } else {
    gaugeProgress.style.stroke = '#10b981';
    classificationBadge.className = 'verdict-badge safe';
    classificationBadge.textContent = 'SAFE';
  }
}

// Render full analysis verdict
function renderVerdict(verdict) {
  if (!verdict) return;

  const score = verdict.risk_score || 0;
  const classification = verdict.classification || 'SAFE';
  updateScoreGauge(score, classification);

  recommendationText.textContent = `Recommendation: ${verdict.recommendation || 'ALLOW'}. ${
    verdict.offline_fallback ? '(Evaluated by local heuristic engine)' : ''
  }`;

  // Multi-Engine Pills
  // 1. DSA Engine
  if (verdict.dsa_verdict) {
    const dsaNorm = verdict.dsa_verdict.toUpperCase();
    dsaVerdictPill.textContent = dsaNorm;
    dsaVerdictPill.className = `engine-val ${dsaNorm === 'HIGH_RISK' ? 'danger' : dsaNorm === 'SUSPICIOUS' ? 'warn' : 'safe'}`;
  } else {
    dsaVerdictPill.textContent = 'CLEAN';
    dsaVerdictPill.className = 'engine-val safe';
  }

  // 2. AIML Engine
  const mlScore = verdict.ml_risk_score !== undefined && verdict.ml_risk_score !== null
    ? Math.round(verdict.ml_risk_score * 100)
    : Math.round(score * 100);
  mlVerdictPill.textContent = `${mlScore}% PHISH`;
  mlVerdictPill.className = `engine-val ${mlScore >= 70 ? 'danger' : mlScore >= 35 ? 'warn' : 'safe'}`;

  // 3. Threat Intel Feed
  const intelVerdict = verdict.threat_intel_verdict || (verdict.threat_intel_score >= 0.7 ? 'HIGH_RISK' : 'CLEAN');
  intelVerdictPill.textContent = intelVerdict === 'HIGH_RISK' ? 'MALICIOUS' : 'CLEAN';
  intelVerdictPill.className = `engine-val ${intelVerdict === 'HIGH_RISK' ? 'danger' : 'safe'}`;

  // Indicators / IOCs
  findingsList.innerHTML = '';
  const indicators = verdict.indicators || [];
  const explanations = verdict.ml_explanations || [];
  const allFindings = [
    ...explanations.map(e => ({ text: e, type: 'ML' })),
    ...indicators.map(i => ({ text: `${i.indicator_type}: ${i.value}`, type: 'IOC' })),
  ];

  iocCountBadge.textContent = `${allFindings.length} Finding${allFindings.length === 1 ? '' : 's'}`;

  if (allFindings.length === 0) {
    const li = document.createElement('li');
    li.className = 'empty-finding';
    li.textContent = 'Target appears consistent with baseline security heuristics.';
    findingsList.appendChild(li);
  } else {
    allFindings.slice(0, 4).forEach(item => {
      const li = document.createElement('li');
      li.textContent = item.text;
      findingsList.appendChild(li);
    });
  }
}

// Load and inspect active tab
async function initActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      targetDomainEl.textContent = 'No active webpage';
      targetUrlEl.textContent = 'Open an HTTP/HTTPS webpage to inspect';
      return;
    }

    currentTabId = tab.id;
    currentUrl = tab.url;

    try {
      const parsed = new URL(tab.url);
      targetDomainEl.textContent = parsed.hostname || tab.url;
      targetUrlEl.textContent = tab.url;
    } catch {
      targetDomainEl.textContent = tab.url;
      targetUrlEl.textContent = tab.url;
    }

    // Request verdict from background service worker
    chrome.runtime.sendMessage({ action: 'GET_ACTIVE_VERDICT' }, (res) => {
      if (res && res.success && res.verdict) {
        renderVerdict(res.verdict);
      } else {
        // Fallback direct scan
        api.analyzeUrl(currentUrl).then(renderVerdict);
      }
    });
  } catch (err) {
    console.error('Failed to initialize active tab in popup:', err);
  }
}

// Event Listeners
btnCopyUrl.addEventListener('click', () => {
  if (!currentUrl) return;
  navigator.clipboard.writeText(currentUrl).then(() => {
    btnCopyUrl.style.color = '#10b981';
    setTimeout(() => { btnCopyUrl.style.color = ''; }, 1500);
  });
});

btnReanalyze.addEventListener('click', async () => {
  if (!currentUrl) return;
  btnReanalyze.disabled = true;
  btnReanalyze.textContent = 'Scanning...';

  try {
    const res = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'REANALYZE_URL', url: currentUrl }, resolve);
    });
    if (res && res.verdict) {
      renderVerdict(res.verdict);
    }
  } catch (err) {
    console.error('Re-scan failed:', err);
  } finally {
    btnReanalyze.disabled = false;
    btnReanalyze.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
      </svg> Re-Scan Target`;
  }
});

btnInvestigate.addEventListener('click', async () => {
  if (!currentUrl) return;
  btnInvestigate.disabled = true;
  btnInvestigate.textContent = 'Investigating...';

  investigationCard.classList.remove('hidden');
  investigationStatus.textContent = 'RUNNING';
  investigationSteps.innerHTML = '<div class="trace-step-item"><span class="step-badge">INIT</span> Launching 5-Phase AegisAgent...</div>';

  try {
    const res = await new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'ESCALATE_INVESTIGATION',
        url: currentUrl,
        depth: 'standard',
        force_escalate: true,
      }, resolve);
    });

    if (res && res.success && res.investigation) {
      const inv = res.investigation;
      investigationStatus.textContent = inv.decision || 'COMPLETED';

      investigationSteps.innerHTML = '';
      if (inv.action_trace && inv.action_trace.length > 0) {
        inv.action_trace.forEach(step => {
          const div = document.createElement('div');
          div.className = 'trace-step-item';
          div.innerHTML = `<span class="step-badge">[${step.action_type}]</span> ${step.tool_name}: ${step.decision_rationale}`;
          investigationSteps.appendChild(div);
        });
      } else {
        const div = document.createElement('div');
        div.className = 'trace-step-item';
        div.innerHTML = `<span class="step-badge">[DECIDE]</span> Recommendation: ${inv.recommended_action}`;
        investigationSteps.appendChild(div);
      }

      if (inv.incident_created && inv.incident_number) {
        currentIncidentId = inv.incident_id;
        incidentPillBox.classList.remove('hidden');
        incidentNumberTag.textContent = inv.incident_number;
      }
    } else {
      investigationStatus.textContent = 'FAILED';
      investigationSteps.innerHTML = `<div class="trace-step-item" style="color: #fb7185;">Investigation error: ${res?.error || 'Unknown'}</div>`;
    }
  } catch (err) {
    investigationStatus.textContent = 'ERROR';
    investigationSteps.innerHTML = `<div class="trace-step-item" style="color: #fb7185;">${err.message}</div>`;
  } finally {
    btnInvestigate.disabled = false;
    btnInvestigate.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="16" x2="12" y2="12"/>
        <line x1="12" y1="8" x2="12.01" y2="8"/>
      </svg> Agent Investigation`;
  }
});

btnRpaContain.addEventListener('click', async () => {
  btnRpaContain.disabled = true;
  btnRpaContain.textContent = 'Dispatching RPA...';

  try {
    // If no incident created yet, create one on the fly or use incident 1
    const incidentId = currentIncidentId || 1;
    const res = await new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'TRIGGER_UIPATH',
        incident_id: incidentId,
        action_type: 'CONTAIN_HOST',
        parameters: { target_url: currentUrl, client: 'CHROME_EXTENSION' }
      }, resolve);
    });

    if (res && res.success && res.action) {
      btnRpaContain.style.background = 'rgba(16, 185, 129, 0.2)';
      btnRpaContain.style.color = '#34d399';
      btnRpaContain.style.borderColor = '#059669';
      btnRpaContain.textContent = `Containment: ${res.action.status}`;
      setTimeout(() => {
        btnRpaContain.style.background = '';
        btnRpaContain.style.color = '';
        btnRpaContain.style.borderColor = '';
        btnRpaContain.disabled = false;
        btnRpaContain.innerHTML = `
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
          </svg> UiPath Containment`;
      }, 3500);
    } else {
      throw new Error(res?.error || 'Trigger failed');
    }
  } catch (err) {
    btnRpaContain.textContent = 'Action Failed';
    setTimeout(() => {
      btnRpaContain.disabled = false;
      btnRpaContain.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
        </svg> UiPath Containment`;
    }, 2000);
  }
});

btnOpenDashboard.addEventListener('click', () => {
  const socUrl = currentUrl
    ? `http://localhost:5173/analyze?url=${encodeURIComponent(currentUrl)}`
    : 'http://localhost:5173';
  chrome.tabs.create({ url: socUrl });
});

// Startup sequence
checkHealthStatus();
initActiveTab();
