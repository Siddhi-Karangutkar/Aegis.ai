/**
 * PhishGuard — Background Service Worker
 * Handles all API communication with the Django backend.
 * Acts as a proxy between content scripts, popup, and the server.
 */

const DEFAULT_API_URL = 'http://localhost:8000';

// ─── Get configured API URL ─────────────────────────────────────────
async function getApiUrl() {
    try {
        const result = await chrome.storage.sync.get(['apiUrl']);
        return result.apiUrl || DEFAULT_API_URL;
    } catch {
        return DEFAULT_API_URL;
    }
}

// ─── Backend Logging ────────────────────────────────────────────────
async function sendBackendLog(source, message) {
    try {
        const apiUrl = await getApiUrl();
        await fetch(`${apiUrl}/api/ext/log/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source, message }),
        });
    } catch (e) {
        // Silent fail if backend is down
    }
    console.log(`[${source}] ${message}`);
}

// ─── API Calls ──────────────────────────────────────────────────────
async function analyzeText(text) {
    const apiUrl = await getApiUrl();
    const resp = await fetch(`${apiUrl}/api/ext/analyze-text/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
    });
    return resp.json();
}

async function analyzeUrl(url, isDownload = false) {
    const apiUrl = await getApiUrl();
    const resp = await fetch(`${apiUrl}/api/ext/analyze-url/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, is_download: isDownload }),
    });
    return resp.json();
}

async function analyzeImage(imageUrl) {
    const apiUrl = await getApiUrl();
    const resp = await fetch(`${apiUrl}/api/ext/analyze-image/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image_url: imageUrl }),
    });
    return resp.json();
}

async function analyzeAttachment(fileData, fileName) {
    const apiUrl = await getApiUrl();
    // Convert base64 back to blob
    const byteChars = atob(fileData);
    const byteArr = new Uint8Array(byteChars.length);
    for (let i = 0; i < byteChars.length; i++) {
        byteArr[i] = byteChars.charCodeAt(i);
    }
    const blob = new Blob([byteArr]);

    const formData = new FormData();
    formData.append('email_text', `Attachment analysis: ${fileName}`);
    formData.append('attachments', blob, fileName);

    const resp = await fetch(`${apiUrl}/api/detect/`, {
        method: 'POST',
        body: formData,
    });
    return resp.json();
}

// ─── Network Isolation Trigger ──────────────────────────────────────
async function triggerIsolation(result) {
    // Only trigger for High/Critical threats
    if (result.risk_level === 'HIGH' || result.risk_level === 'CRITICAL' || result.prediction === 'Malicious') {
        try {
            console.warn('[PhishGuard] Critical threat! Triggering network isolation...');
            await fetch('http://127.0.0.1:5001/isolate', {
                method: 'POST',
                mode: 'no-cors' // Agent is local and doesn't need full CORS for this fire-and-forget call
            });

            // Notify popup/content that isolation is active
            chrome.storage.local.set({ isolationActive: true, isolationStartTime: Date.now() });
        } catch (e) {
            console.error('[PhishGuard] Failed to reach local agent for isolation:', e.message);
        }
    }
}

// ─── Message Handler ────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const { action, data } = message;

    const handleAsync = async () => {
        try {
            let result;
            switch (action) {
                case 'analyzeUrl':
                    sendBackendLog('Trigger:ContentScript', `Analyzing URL from page: ${data.url.substring(0, 50)}...`);
                    result = await analyzeUrl(data.url);
                    break;
                case 'analyzeText':
                    result = await analyzeText(data.text);
                    break;
                case 'analyzeImage':
                    sendBackendLog('Trigger:ContentScript', `Analyzing Image from page: ${data.imageUrl.substring(0, 50)}...`);
                    result = await analyzeImage(data.imageUrl);
                    break;
                case 'analyzePage':
                    // Get page content from active tab
                    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                    if (tab) {
                        const [{ result: pageText }] = await chrome.scripting.executeScript({
                            target: { tabId: tab.id },
                            func: () => document.body.innerText,
                        });
                        result = await analyzeText(pageText || '');
                    } else {
                        result = { prediction: 'Error', confidence: 0, risk_level: 'UNKNOWN', reasons: ['No active tab'] };
                    }
                    break;
                case 'getPageData':
                    // Return current tab URL
                    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
                    result = { url: activeTab?.url || '', title: activeTab?.title || '' };
                    break;
                case 'analyzeAttachment':
                    result = await analyzeAttachment(data.fileData, data.fileName);
                    break;
                default:
                    result = { error: `Unknown action: ${action}` };
            }

            // Trigger isolation check
            if (result && !result.error) {
                triggerIsolation(result);
            }

            sendResponse({ success: true, data: result });
        } catch (error) {
            console.error('[PhishGuard] Background error:', error);
            sendResponse({
                success: false,
                error: error.message || 'Backend connection failed. Is the server running?'
            });
        }
    };

    handleAsync();
    return true; // Keep message channel open for async response
});

// ─── Auto-scan on tab update ────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && !tab.url.startsWith('chrome://')) {
        try {
            sendBackendLog('Trigger:TabUpdate', `Auto-scanning newly loaded tab: ${tab.url.substring(0, 50)}...`);
            const result = await analyzeUrl(tab.url);

            // Store result for popup to access
            await chrome.storage.local.set({
                [`scan_${tabId}`]: {
                    url: tab.url,
                    result,
                    timestamp: Date.now(),
                }
            });

            // Update badge based on result
            const color = result.risk_level === 'HIGH' ? '#ff3333'
                        : result.risk_level === 'MEDIUM' ? '#FFB300'
                        : '#00ff88';

            await chrome.action.setBadgeBackgroundColor({ color, tabId });
            await chrome.action.setBadgeText({
                text: result.risk_level === 'LOW' ? '✓' : '!',
                tabId,
            });

            // Trigger isolation for auto-scan results
            triggerIsolation(result);
        } catch (e) {
            // Backend might not be running — silent fail
            console.warn('[PhishGuard] Auto-scan failed:', e.message);
        }
    }
});

// ─── Download Interceptor (Sandbox) ───────────────────────────────
// Keep track of downloads we've already analyzed so we don't get into an infinite loop when resuming
const analyzedDownloads = new Set();

chrome.downloads.onCreated.addListener(async (downloadItem) => {
    // Ignore if we already analyzed it or if it's not an http/https URL
    if (analyzedDownloads.has(downloadItem.id) || !downloadItem.url.startsWith('http')) return;

    sendBackendLog('Trigger:Download', `[onCreated] Intercepted download #${downloadItem.id}: "${downloadItem.filename || downloadItem.url.substring(0, 60)}"`);
    
    // Pause the download strictly BEFORE it hits the disk
    try {
        await chrome.downloads.pause(downloadItem.id);
        sendBackendLog('Sandbox', `Download #${downloadItem.id} paused. Sending to Secure Docker Sandbox...`);
        
        // Show scanning notification
        chrome.notifications.create(`scan-${downloadItem.id}`, {
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: 'PhishGuard Sandbox',
            message: `Analyzing file in secure container: ${downloadItem.filename || 'unknown'}`,
            priority: 0
        });

        // Analyze URL (which triggers remote file Docker sandbox on backend)
        const result = await analyzeUrl(downloadItem.url, true);
        
        // Mark as analyzed so we don't scan it again if we resume it
        analyzedDownloads.add(downloadItem.id);

        if (result && (result.risk_level === 'HIGH' || result.risk_level === 'CRITICAL' || result.risk_level === 'MEDIUM')) {
            // Threat detected! Cancel the download.
            sendBackendLog('Action:Block', `THREAT DETECTED! Score: ${result.confidence}%. Canceling download #${downloadItem.id}!`);
            await chrome.downloads.cancel(downloadItem.id);

            // Notify user of the block
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: 'CRITICAL THREAT BLOCKED',
                message: `PhishGuard sandbox blocked a malicious file: ${downloadItem.filename}\nRisk: ${result.confidence}%`,
                priority: 2
            });

            // Trigger network isolation just in case
            triggerIsolation(result);

        } else {
            // File is safe. Resume download.
            sendBackendLog('Action:Allow', `File is safe (${result?.risk_level || 'LOW'}). Resuming download #${downloadItem.id}.`);
            await chrome.downloads.resume(downloadItem.id);
            
            // Update scanning notification to clear
            chrome.notifications.update(`scan-${downloadItem.id}`, {
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: 'Scan Complete',
                message: `File is safe: ${downloadItem.filename}`
            });
            // Clear notification after 3s
            setTimeout(() => chrome.notifications.clear(`scan-${downloadItem.id}`), 3000);
        }

    } catch (e) {
        sendBackendLog('Error', `Failed to process download #${downloadItem.id}: ${e.message}`);
        // Fallback: If our scan crashes, we resume the file so we don't permanently break downloading
        analyzedDownloads.add(downloadItem.id);
        try { chrome.downloads.resume(downloadItem.id); } catch (_) {}
    }
});

// ─── Startup Self-Check ────────────────────────────────────────────
console.log('[PhishGuard] Background service worker loaded');
console.log('[PhishGuard] Download interceptor: REGISTERED');
console.log('[PhishGuard] Downloads API available:', typeof chrome.downloads !== 'undefined');
sendBackendLog('Startup', 'Background service worker loaded. Download interceptor ACTIVE.');

