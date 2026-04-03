/**
 * PhishGuard — Popup Logic
 * Handles tab switching, API calls via background worker, and result display.
 */

document.addEventListener('DOMContentLoaded', () => {
    // ─── Tab Switching ──────────────────────────────────────────
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
        });
    });

    // ─── Load Current URL ───────────────────────────────────────
    chrome.runtime.sendMessage({ action: 'getPageData' }, (resp) => {
        if (resp?.success) {
            document.getElementById('currentUrl').textContent = resp.data.url || 'No URL available';
            loadAutoScanResult();
        }
    });

    // ─── Load Auto-Scan Result ──────────────────────────────────
    async function loadAutoScanResult() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab) return;

        const stored = await chrome.storage.local.get([`scan_${tab.id}`]);
            const scanData = stored[`scan_${tab.id}`];

            if (scanData && scanData.result) {
                showBanner(scanData.result);
            }
        } catch (e) {
            console.warn('Could not load auto-scan result:', e);
        }
    }

    // ─── Show Banner ────────────────────────────────────────────
    function showBanner(result) {
        const banner = document.getElementById('autoScanBanner');
        const dot = document.getElementById('statusDot');

        banner.classList.remove('hidden', 'safe', 'warning', 'danger');

        const level = result.risk_level || 'LOW';
        const cls = level === 'HIGH' ? 'danger' : level === 'MEDIUM' ? 'warning' : 'safe';

        banner.classList.add(cls);
        dot.className = `status-dot ${cls}`;

        document.getElementById('bannerIcon').textContent =
            cls === 'danger' ? '⚠' : cls === 'warning' ? '◆' : '✓';

        document.getElementById('bannerTitle').textContent =
            cls === 'danger' ? '⚠ Suspicious URL Detected'
            : cls === 'warning' ? '◆ Caution Advised'
            : '✓ URL Appears Safe';

        document.getElementById('bannerSubtitle').textContent =
            (result.reasons && result.reasons[0]) || 'Auto-scan complete';

        document.getElementById('bannerScore').textContent = `${result.confidence}%`;
    }

    // ─── Generic API Call ───────────────────────────────────────
    function sendMessage(action, data) {
        return new Promise((resolve, reject) => {
            chrome.runtime.sendMessage({ action, data }, (resp) => {
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                } else if (!resp?.success) {
                    reject(new Error(resp?.error || 'Unknown error'));
                } else {
                    resolve(resp.data);
                }
            });
        });
    }

    // ─── Render Result ──────────────────────────────────────────
    function renderResult(container, result) {
        const level = result.risk_level || 'LOW';
        const cls = level === 'HIGH' ? 'danger' : level === 'MEDIUM' ? 'warning' : 'safe';

        let html = `
            <div class="result-header">
                <span class="result-prediction ${cls}">${result.prediction}</span>
                <span class="result-confidence ${cls}">${result.confidence}%</span>
            </div>
            <span class="risk-badge ${level}">RISK: ${level}</span>
        `;

        if (result.reasons && result.reasons.length > 0) {
            html += '<ul class="reasons-list">';
            result.reasons.forEach(r => {
                html += `<li>${escapeHtml(r)}</li>`;
            });
            html += '</ul>';
        }

        if (level === 'HIGH') {
            html += `
                <div class="warning-box">
                    <h4>⚠ Security Advisory</h4>
                    <ul>
                        <li>Avoid entering personal information</li>
                        <li>Do not click unknown links</li>
                        <li>Verify sender identity independently</li>
                        <li>Report suspicious content</li>
                    </ul>
                </div>
            `;
        }

        if (result.scan_type === 'sandbox' && result.sandbox_analysis) {
            const sa = result.sandbox_analysis;
            html += `<div style="margin-top:10px; padding:8px; background:rgba(0,240,255,0.03); border:1px solid var(--border); border-radius:6px;">`;
            html += `<div style="font-size:10px; color:var(--accent); font-weight:700; margin-bottom:4px; letter-spacing:1px;">SANDBOX ANALYSIS</div>`;
            if (sa.detected_type) html += `<div style="font-size:10px; color:var(--text-secondary);">Type: <strong>${sa.detected_type}</strong></div>`;
            if (sa.entropy) html += `<div style="font-size:10px; color:var(--text-secondary);">Entropy: <strong>${sa.entropy}</strong></div>`;
            if (sa.dangerous_capabilities?.length > 0) {
                html += `<div style="font-size:10px; color:var(--danger); margin-top:4px;">Capabilities: ${sa.dangerous_capabilities.join(', ')}</div>`;
            }
            html += `</div>`;
        }

        if (result.ocr_text_preview) {
            html += `<div style="margin-top:10px; padding:8px; background:rgba(0,240,255,0.03); border:1px solid var(--border); border-radius:6px;">`;
            html += `<div style="font-size:10px; color:var(--accent); font-weight:700; margin-bottom:4px; letter-spacing:1px;">OCR EXTRACTED TEXT</div>`;
            html += `<div style="font-size:10px; color:var(--text-secondary); line-height:1.4; max-height:60px; overflow:hidden;">${escapeHtml(result.ocr_text_preview)}</div>`;
            html += `</div>`;
        }

        container.innerHTML = html;
        container.classList.remove('hidden');
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function showLoading(btn, container) {
        btn.disabled = true;
        btn.classList.add('scanning');
        btn.innerHTML = '<span class="spinner"></span> ANALYZING...';
        container.classList.add('hidden');
    }

    function resetBtn(btn, originalText) {
        btn.disabled = false;
        btn.classList.remove('scanning');
        btn.innerHTML = originalText;
    }

    function showError(container, message) {
        container.innerHTML = `
            <div style="color: var(--danger); font-size: 11px; text-align: center; padding: 12px;">
                <div style="font-size: 20px; margin-bottom: 6px;">⚠</div>
                <strong>Connection Error</strong>
                <p style="color: var(--text-secondary); margin-top: 4px; font-size: 10px;">${escapeHtml(message)}</p>
                <p style="color: var(--text-dim); margin-top: 4px; font-size: 9px;">Make sure the Django server is running at the configured URL.</p>
            </div>
        `;
        container.classList.remove('hidden');

        document.getElementById('connectionStatus').textContent = '● Disconnected';
        document.getElementById('connectionStatus').classList.add('error');
    }

    // ─── URL Scan ───────────────────────────────────────────────
    const scanUrlBtn = document.getElementById('scanUrlBtn');
    const urlResult = document.getElementById('urlResult');
    const urlBtnText = '<span class="btn-icon">🔍</span> SCAN URL';

    scanUrlBtn.addEventListener('click', async () => {
        showLoading(scanUrlBtn, urlResult);
        try {
            const url = document.getElementById('currentUrl').textContent;
            const result = await sendMessage('analyzeUrl', { url });
            renderResult(urlResult, result);
            showBanner(result);
        } catch (e) {
            showError(urlResult, e.message);
        } finally {
            resetBtn(scanUrlBtn, urlBtnText);
        }
    });

    // ─── Page Scan ──────────────────────────────────────────────
    const scanPageBtn = document.getElementById('scanPageBtn');
    const pageResult = document.getElementById('pageResult');
    const pageBtnText = '<span class="btn-icon">📑</span> SCAN PAGE CONTENT';

    scanPageBtn.addEventListener('click', async () => {
        showLoading(scanPageBtn, pageResult);
        try {
            const result = await sendMessage('analyzePage', {});
            renderResult(pageResult, result);
        } catch (e) {
            showError(pageResult, e.message);
        } finally {
            resetBtn(scanPageBtn, pageBtnText);
        }
    });

    // ─── Message Scan ───────────────────────────────────────────
    const scanMsgBtn = document.getElementById('scanMsgBtn');
    const msgResult = document.getElementById('msgResult');
    const msgBtnText = '<span class="btn-icon">🔍</span> ANALYZE MESSAGE';

    scanMsgBtn.addEventListener('click', async () => {
        const text = document.getElementById('messageInput').value.trim();
        if (!text) {
            document.getElementById('messageInput').style.borderColor = 'var(--danger)';
            setTimeout(() => document.getElementById('messageInput').style.borderColor = '', 1500);
            return;
        }
        showLoading(scanMsgBtn, msgResult);
        try {
            const result = await sendMessage('analyzeText', { text });
            renderResult(msgResult, result);
        } catch (e) {
            showError(msgResult, e.message);
        } finally {
            resetBtn(scanMsgBtn, msgBtnText);
        }
    });

    // ─── Settings Button ────────────────────────────────────────
    document.getElementById('settingsBtn').addEventListener('click', () => {
        chrome.runtime.openOptionsPage();
    });

    // ─── Connection Check ───────────────────────────────────────
    async function checkConnection() {
        try {
            const result = await chrome.storage.sync.get(['apiUrl']);
            const apiUrl = result.apiUrl || 'http://localhost:8000';
            const resp = await fetch(`${apiUrl}/api/ext/analyze-text/`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: 'connection test' }),
            });
            if (resp.ok) {
                document.getElementById('connectionStatus').textContent = '● Connected';
                document.getElementById('connectionStatus').classList.remove('error');
            }
        } catch {
            document.getElementById('connectionStatus').textContent = '● Disconnected';
            document.getElementById('connectionStatus').classList.add('error');
        }
    }

    checkConnection();
});
