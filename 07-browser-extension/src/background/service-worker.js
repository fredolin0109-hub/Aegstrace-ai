/**
 * AEGISTRACE Chrome Extension - Background Service Worker (Manifest V3)
 * Handles real-time navigation events, background threat inspection,
 * badge status updates, and IPC message routing.
 */

import { api } from '../services/api.js';

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes cache

// Helper to check if URL should be analyzed
function isAnalyzableUrl(url) {
  if (!url || typeof url !== 'string') return false;
  return url.startsWith('http://') || url.startsWith('https://');
}

// Update Chrome action badge for tab
async function updateTabBadge(tabId, classification, riskScore) {
  try {
    const scorePct = Math.round(riskScore * 100);
    if (classification === 'HIGH_RISK') {
      await chrome.action.setBadgeText({ tabId, text: `${scorePct}%` });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#f43f5e' });
    } else if (classification === 'SUSPICIOUS') {
      await chrome.action.setBadgeText({ tabId, text: 'WARN' });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#f59e0b' });
    } else {
      await chrome.action.setBadgeText({ tabId, text: 'OK' });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#10b981' });
    }
  } catch (err) {
    console.debug('Failed to set badge for tab:', tabId, err);
  }
}

// Inspect active tab URL with caching
async function inspectTab(tabId, url) {
  if (!isAnalyzableUrl(url)) {
    try {
      await chrome.action.setBadgeText({ tabId, text: '' });
    } catch {}
    return null;
  }

  // Check persistent storage cache
  const cacheKey = `verdict_${url}`;
  const stored = await chrome.storage.local.get(cacheKey);
  const now = Date.now();

  if (stored[cacheKey] && (now - stored[cacheKey].timestamp) < CACHE_TTL_MS) {
    const cachedData = stored[cacheKey].data;
    await updateTabBadge(tabId, cachedData.classification, cachedData.risk_score);
    return cachedData;
  }

  // Run analysis via API service
  const result = await api.analyzeUrl(url);

  // Store in cache
  await chrome.storage.local.set({
    [cacheKey]: {
      timestamp: now,
      data: result,
    },
    last_analyzed_tab: {
      tabId,
      url,
      verdict: result,
      timestamp: now,
    }
  });

  // Update badge UI
  await updateTabBadge(tabId, result.classification, result.risk_score);

  // If High Risk, notify content script to render intercepted warning banner
  if (result.classification === 'HIGH_RISK') {
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: 'AEGIS_HIGH_RISK_WARNING',
        data: result,
      });
    } catch (err) {
      console.debug('Content script not yet ready on tab:', tabId);
    }
  }

  return result;
}

// Navigation event listener
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    inspectTab(tabId, tab.url).catch(err => {
      console.error('Error during tab inspection:', err);
    });
  }
});

// Tab switch listener
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url) {
      await inspectTab(activeInfo.tabId, tab.url);
    }
  } catch (err) {
    console.debug('Error in tab onActivated:', err);
  }
});

// IPC Message Listener for popup and content script actions
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      switch (message.action) {
        case 'GET_ACTIVE_VERDICT': {
          const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (!activeTab || !activeTab.url) {
            sendResponse({ success: false, error: 'No active tab URL accessible' });
            return;
          }
          const verdict = await inspectTab(activeTab.id, activeTab.url);
          sendResponse({ success: true, tab: activeTab, verdict });
          break;
        }

        case 'REANALYZE_URL': {
          const urlToScan = message.url;
          if (!urlToScan) {
            sendResponse({ success: false, error: 'No URL provided' });
            return;
          }
          // Invalidate cache
          const cacheKey = `verdict_${urlToScan}`;
          await chrome.storage.local.remove(cacheKey);

          const result = await api.analyzeUrl(urlToScan);
          if (sender.tab?.id) {
            await updateTabBadge(sender.tab.id, result.classification, result.risk_score);
          }
          sendResponse({ success: true, verdict: result });
          break;
        }

        case 'ESCALATE_INVESTIGATION': {
          const { url, depth, force_escalate } = message;
          const result = await api.investigateUrl(url, { depth, force_escalate });
          sendResponse({ success: true, investigation: result });
          break;
        }

        case 'TRIGGER_UIPATH': {
          const { incident_id, action_type, parameters } = message;
          const result = await api.triggerUiPathAction(incident_id, action_type, parameters);
          sendResponse({ success: true, action: result });
          break;
        }

        case 'CHECK_UIPATH_STATUS': {
          const { execution_id } = message;
          const status = await api.getUiPathStatus(execution_id);
          sendResponse({ success: true, status });
          break;
        }

        case 'CHECK_HEALTH': {
          const health = await api.checkHealth();
          sendResponse({ success: true, health });
          break;
        }

        default:
          sendResponse({ success: false, error: `Unknown action: ${message.action}` });
      }
    } catch (err) {
      console.error('Service worker error handling message:', err);
      sendResponse({ success: false, error: err.message });
    }
  })();

  return true; // Keep channel open for async sendResponse
});
