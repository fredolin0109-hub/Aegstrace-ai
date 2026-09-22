/**
 * AEGISTRACE Content Script
 * Receives security alerts from background service worker and renders
 * defensive warning intercept overlays to protect users from high-risk credential harvesting.
 */

(() => {
  // Prevent duplicate execution
  if (window.__AEGISTRACE_CONTENT_INJECTED__) return;
  window.__AEGISTRACE_CONTENT_INJECTED__ = true;

  // Listen for security messages from background service worker
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'AEGIS_HIGH_RISK_WARNING') {
      showThreatWarning(message.data);
    }
  });

  function showThreatWarning(data) {
    if (document.getElementById('aegistrace-warning-overlay')) {
      return; // Already visible
    }

    const overlay = document.createElement('div');
    overlay.id = 'aegistrace-warning-overlay';

    const riskScore = Math.round((data.risk_score || 0) * 100);
    const domain = data.domain || window.location.hostname;
    const url = data.url || window.location.href;
    const confidence = Math.round((data.confidence || 0.95) * 100);

    overlay.innerHTML = `
      <div id="aegistrace-warning-box">
        <svg class="aegis-shield-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>

        <h2 class="aegis-title">AEGISTRACE // THREAT DETECTED</h2>
        <div class="aegis-subtitle">CRITICAL PHISHING & CREDENTIAL HARVESTER HAZARD</div>

        <div class="aegis-url-badge">
          Target: <span>${escapeHtml(domain)}</span><br/>
          <small style="opacity: 0.7">${escapeHtml(url)}</small>
        </div>

        <div class="aegis-risk-stats">
          <div class="aegis-stat-item">
            <span class="aegis-stat-label">Risk Probability</span>
            <span class="aegis-stat-val">${riskScore}%</span>
          </div>
          <div class="aegis-stat-item">
            <span class="aegis-stat-label">AI Confidence</span>
            <span class="aegis-stat-val">${confidence}%</span>
          </div>
          <div class="aegis-stat-item">
            <span class="aegis-stat-label">Recommended Action</span>
            <span class="aegis-stat-val" style="color: #fda4af;">${escapeHtml(data.recommendation || 'BLOCK')}</span>
          </div>
        </div>

        <p style="font-size: 13px; color: #94a3b8; line-height: 1.5; margin-bottom: 24px;">
          This web destination was identified as an active phishing vector by the AEGISTRACE multi-engine inspection pipeline. Entering credentials, tokens, or personal identifiers may compromise your system.
        </p>

        <div class="aegis-actions">
          <button id="aegis-btn-safe-exit" class="aegis-btn-safe">
            Navigate to Safety (Exit)
          </button>
          <button id="aegis-btn-dismiss" class="aegis-btn-bypass">
            I Understand the Risk (Proceed)
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    // Wire action buttons
    document.getElementById('aegis-btn-safe-exit')?.addEventListener('click', () => {
      window.location.href = 'about:blank';
    });

    document.getElementById('aegis-btn-dismiss')?.addEventListener('click', () => {
      overlay.remove();
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
})();
