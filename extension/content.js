/**
 * PhishGuard — Content Script
 * Runs on every page to detect suspicious links, files, and images.
 * Injects clickable risk badges that show detailed analysis popups.
 */

(function () {
    'use strict';

    // Prevent multiple injections
    if (window.__phishguardInjected) return;
    window.__phishguardInjected = true;

    const FILE_EXTENSIONS = [
        '.pdf', '.exe', '.bat', '.cmd', '.scr', '.zip', '.rar', '.7z',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.js', '.vbs', '.ps1', '.msi', '.hta', '.jar', '.apk',
        '.iso', '.img', '.dmg',
    ];

    const IMAGE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.webp', '.bmp', '.gif', '.tiff'];

    // ─── Inject Global Styles ───────────────────────────────────────
    const styleSheet = document.createElement('style');
    styleSheet.textContent = `
        .phishguard-modal-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(4px);
            z-index: 2147483646;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: pgFadeIn 0.2s ease;
        }
        .phishguard-modal {
            background: #0f1525;
            border: 1px solid rgba(0, 240, 255, 0.2);
            border-radius: 12px;
            width: 420px;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 25px 60px rgba(0, 0, 0, 0.6), 0 0 40px rgba(0, 240, 255, 0.08);
            animation: pgSlideIn 0.3s ease;
            font-family: system-ui, -apple-system, sans-serif;
            color: #e8eaf0;
        }
        .phishguard-modal * { box-sizing: border-box; margin: 0; padding: 0; }
        .phishguard-modal-header {
            display: flex; justify-content: space-between; align-items: center;
            padding: 16px 20px;
            border-bottom: 1px solid rgba(0, 240, 255, 0.1);
        }
        .phishguard-modal-header h2 {
            font-size: 13px; font-weight: 800; letter-spacing: 2px;
            color: #00f0ff; text-transform: uppercase;
        }
        .phishguard-modal-close {
            background: none; border: 1px solid rgba(255,255,255,0.1);
            color: rgba(255,255,255,0.5); font-size: 16px;
            width: 28px; height: 28px; border-radius: 6px;
            cursor: pointer; display: flex; align-items: center; justify-content: center;
            transition: all 0.2s;
        }
        .phishguard-modal-close:hover {
            border-color: #ff3333; color: #ff3333; background: rgba(255,51,51,0.1);
        }
        .phishguard-modal-body { padding: 20px; }
        .phishguard-modal-verdict {
            display: flex; align-items: center; justify-content: space-between;
            padding: 14px 16px; border-radius: 8px; margin-bottom: 16px;
        }
        .phishguard-modal-verdict.danger {
            background: rgba(255,51,51,0.08); border: 1px solid rgba(255,51,51,0.2);
        }
        .phishguard-modal-verdict.warning {
            background: rgba(255,179,0,0.08); border: 1px solid rgba(255,179,0,0.2);
        }
        .phishguard-modal-verdict.safe {
            background: rgba(0,255,136,0.08); border: 1px solid rgba(0,255,136,0.2);
        }
        .phishguard-verdict-label {
            font-size: 16px; font-weight: 900; letter-spacing: 1px;
        }
        .phishguard-verdict-label.danger { color: #ff3333; }
        .phishguard-verdict-label.warning { color: #FFB300; }
        .phishguard-verdict-label.safe { color: #00ff88; }
        .phishguard-verdict-score {
            font-size: 28px; font-weight: 900; letter-spacing: 1px;
        }
        .phishguard-verdict-score.danger { color: #ff3333; }
        .phishguard-verdict-score.warning { color: #FFB300; }
        .phishguard-verdict-score.safe { color: #00ff88; }
        .phishguard-section-title {
            font-size: 10px; font-weight: 700; letter-spacing: 1.5px;
            color: #00f0ff; text-transform: uppercase;
            margin: 16px 0 8px 0;
        }
        .phishguard-info-row {
            display: flex; justify-content: space-between; align-items: center;
            padding: 6px 0; font-size: 12px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
        }
        .phishguard-info-label { color: rgba(255,255,255,0.4); }
        .phishguard-info-value { color: #e8eaf0; font-weight: 600; text-align: right; max-width: 240px; word-break: break-all; }
        .phishguard-reason {
            padding: 6px 0 6px 14px; font-size: 11px;
            color: rgba(255,255,255,0.6); position: relative; line-height: 1.5;
        }
        .phishguard-reason::before {
            content: '›'; position: absolute; left: 0;
            color: #00f0ff; font-weight: bold;
        }
        .phishguard-warning-box {
            margin-top: 16px; padding: 12px 14px;
            background: rgba(255,51,51,0.06);
            border: 1px solid rgba(255,51,51,0.15);
            border-radius: 8px;
        }
        .phishguard-warning-box h4 {
            color: #ff3333; font-size: 11px; font-weight: 700;
            letter-spacing: 1px; margin-bottom: 8px;
        }
        .phishguard-warning-box li {
            font-size: 10px; color: rgba(255,255,255,0.5);
            padding: 2px 0; list-style: none;
            padding-left: 12px; position: relative;
        }
        .phishguard-warning-box li::before {
            content: '•'; position: absolute; left: 0; color: #ff3333;
        }
        .phishguard-sandbox-box {
            margin-top: 12px; padding: 10px 14px;
            background: rgba(0,240,255,0.03);
            border: 1px solid rgba(0,240,255,0.1);
            border-radius: 8px;
        }
        .phishguard-sandbox-title {
            font-size: 9px; font-weight: 700; letter-spacing: 1.5px;
            color: #00f0ff; margin-bottom: 6px;
        }
        .phishguard-sandbox-row {
            font-size: 10px; color: rgba(255,255,255,0.5); padding: 2px 0;
        }
        .phishguard-sandbox-row strong { color: #e8eaf0; }
        .phishguard-ocr-box {
            margin-top: 12px; padding: 10px 14px;
            background: rgba(0,240,255,0.03);
            border: 1px solid rgba(0,240,255,0.1);
            border-radius: 8px; max-height: 100px; overflow-y: auto;
        }
        @keyframes pgFadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes pgSlideIn { from { opacity: 0; transform: translateY(20px) scale(0.96); } to { opacity: 1; transform: translateY(0) scale(1); } }
        .phishguard-badge-clickable {
            cursor: pointer !important;
            pointer-events: auto !important;
        }
        .phishguard-badge-clickable:hover {
            filter: brightness(1.3);
            transform: scale(1.05);
        }
        .phishguard-modal::-webkit-scrollbar { width: 4px; }
        .phishguard-modal::-webkit-scrollbar-track { background: #0f1525; }
        .phishguard-modal::-webkit-scrollbar-thumb { background: rgba(0,240,255,0.2); border-radius: 4px; }
    `;
    document.head.appendChild(styleSheet);

    // ─── Show Detail Modal ──────────────────────────────────────────
    function showDetailModal(analysisData, sourceUrl) {
        // Remove any existing modal
        document.querySelector('.phishguard-modal-overlay')?.remove();

        const r = analysisData;
        const level = r.risk_level || 'LOW';
        const cls = level === 'HIGH' ? 'danger' : level === 'MEDIUM' ? 'warning' : 'safe';

        const overlay = document.createElement('div');
        overlay.className = 'phishguard-modal-overlay';
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.remove();
        });

        let reasonsHtml = '';
        if (r.reasons && r.reasons.length > 0) {
            reasonsHtml = r.reasons.map(reason =>
                `<div class="phishguard-reason">${escapeHtml(reason)}</div>`
            ).join('');
        } else {
            reasonsHtml = '<div style="font-size:11px; color:rgba(255,255,255,0.3); padding:8px 0;">No specific threats identified.</div>';
        }

        let sandboxHtml = '';
        if (r.sandbox_analysis) {
            const sa = r.sandbox_analysis;
            sandboxHtml = `
                <div class="phishguard-sandbox-box">
                    <div class="phishguard-sandbox-title">SANDBOX ANALYSIS</div>
                    ${sa.detected_type ? `<div class="phishguard-sandbox-row">Detected Type: <strong>${escapeHtml(sa.detected_type)}</strong></div>` : ''}
                    ${sa.filename ? `<div class="phishguard-sandbox-row">Filename: <strong>${escapeHtml(sa.filename)}</strong></div>` : ''}
                    ${sa.file_size ? `<div class="phishguard-sandbox-row">File Size: <strong>${(sa.file_size / 1024).toFixed(1)} KB</strong></div>` : ''}
                    ${sa.entropy ? `<div class="phishguard-sandbox-row">Entropy: <strong>${sa.entropy}</strong> ${sa.entropy > 7.5 ? '<span style="color:#ff3333;">⚠ HIGH</span>' : '<span style="color:#00ff88;">Normal</span>'}</div>` : ''}
                    ${sa.dangerous_capabilities?.length > 0 ? `<div class="phishguard-sandbox-row" style="color:#ff3333;">Capabilities: <strong>${sa.dangerous_capabilities.join(', ')}</strong></div>` : ''}
                </div>
            `;
        }

        let ocrHtml = '';
        if (r.ocr_text_preview) {
            ocrHtml = `
                <div class="phishguard-ocr-box">
                    <div class="phishguard-sandbox-title">OCR EXTRACTED TEXT</div>
                    <div style="font-size:10px; color:rgba(255,255,255,0.5); line-height:1.5; white-space:pre-wrap;">${escapeHtml(r.ocr_text_preview)}</div>
                </div>
            `;
        }

        let warningHtml = '';
        if (level === 'HIGH') {
            warningHtml = `
                <div class="phishguard-warning-box">
                    <h4>⚠ SECURITY ADVISORY</h4>
                    <ul>
                        <li>Do not download or open this file</li>
                        <li>Avoid entering personal information</li>
                        <li>Do not click unknown links</li>
                        <li>Verify the source independently</li>
                        <li>Report suspicious content to IT security</li>
                    </ul>
                </div>
            `;
        }

        overlay.innerHTML = `
            <div class="phishguard-modal">
                <div class="phishguard-modal-header">
                    <h2>🛡 PhishGuard Analysis</h2>
                    <button class="phishguard-modal-close" id="pgModalClose">✕</button>
                </div>
                <div class="phishguard-modal-body">
                    <div class="phishguard-modal-verdict ${cls}">
                        <div>
                            <div class="phishguard-verdict-label ${cls}">${r.prediction || 'Unknown'}</div>
                            <div style="font-size:10px; color:rgba(255,255,255,0.4); margin-top:2px;">RISK LEVEL: ${level}</div>
                        </div>
                        <div class="phishguard-verdict-score ${cls}">${r.confidence}%</div>
                    </div>

                    <div class="phishguard-info-row">
                        <span class="phishguard-info-label">Scan Type</span>
                        <span class="phishguard-info-value">${r.scan_type || 'standard'}</span>
                    </div>
                    <div class="phishguard-info-row">
                        <span class="phishguard-info-label">Source</span>
                        <span class="phishguard-info-value">${escapeHtml(sourceUrl?.substring(0, 60) || 'N/A')}${sourceUrl?.length > 60 ? '...' : ''}</span>
                    </div>
                    ${r.breakdown ? `
                        <div class="phishguard-info-row">
                            <span class="phishguard-info-label">URL Score</span>
                            <span class="phishguard-info-value">${r.breakdown.url_score !== undefined ? (r.breakdown.url_score * 100).toFixed(0) + '%' : '—'}</span>
                        </div>
                        <div class="phishguard-info-row">
                            <span class="phishguard-info-label">Text Score</span>
                            <span class="phishguard-info-value">${r.breakdown.text_score !== undefined ? (r.breakdown.text_score * 100).toFixed(0) + '%' : '—'}</span>
                        </div>
                        <div class="phishguard-info-row">
                            <span class="phishguard-info-label">Rule Score</span>
                            <span class="phishguard-info-value">${r.breakdown.rule_score !== undefined ? (r.breakdown.rule_score * 100).toFixed(0) + '%' : '—'}</span>
                        </div>
                    ` : ''}

                    <div class="phishguard-section-title">Detection Reasons</div>
                    ${reasonsHtml}

                    ${sandboxHtml}
                    ${ocrHtml}
                    ${warningHtml}
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        // Close button
        overlay.querySelector('#pgModalClose').addEventListener('click', () => overlay.remove());

        // ESC to close
        const escHandler = (e) => {
            if (e.key === 'Escape') {
                overlay.remove();
                document.removeEventListener('keydown', escHandler);
            }
        };
        document.addEventListener('keydown', escHandler);
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    }

    // ─── Create Badge Element (Clickable) ───────────────────────────
    function createBadge(type, text, analysisData, sourceUrl) {
        const badge = document.createElement('span');
        badge.className = 'phishguard-badge phishguard-badge-clickable';

        const colors = {
            safe: { bg: 'rgba(0,255,136,0.15)', border: '#00ff88', text: '#00ff88' },
            warning: { bg: 'rgba(255,179,0,0.15)', border: '#FFB300', text: '#FFB300' },
            danger: { bg: 'rgba(255,51,51,0.15)', border: '#ff3333', text: '#ff3333' },
            scanning: { bg: 'rgba(0,240,255,0.1)', border: '#00f0ff', text: '#00f0ff' },
        };

        const c = colors[type] || colors.scanning;

        badge.style.cssText = `
            display: inline-flex;
            align-items: center;
            gap: 4px;
            margin-left: 6px;
            padding: 2px 8px;
            font-size: 10px;
            font-family: system-ui, sans-serif;
            font-weight: 700;
            letter-spacing: 0.5px;
            color: ${c.text};
            background: ${c.bg};
            border: 1px solid ${c.border};
            border-radius: 4px;
            white-space: nowrap;
            z-index: 99999;
            cursor: pointer;
            pointer-events: auto;
            transition: all 0.2s ease;
        `;

        const icon = type === 'safe' ? '✓' : type === 'danger' ? '⚠' : type === 'warning' ? '◆' : '⟳';
        badge.textContent = `${icon} ${text}`;

        // Click to show detailed analysis
        if (analysisData) {
            badge.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                showDetailModal(analysisData, sourceUrl);
            });
        }

        return badge;
    }

    // ─── Scan Download Links ────────────────────────────────────────
    async function scanFileLinks() {
        const links = document.querySelectorAll('a[href]');
        const scannedUrls = new Set();

        for (const link of links) {
            const href = link.href?.toLowerCase() || '';
            if (scannedUrls.has(href) || !href.startsWith('http')) continue;

            // Check if link points to a file
            const isFile = FILE_EXTENSIONS.some(ext => href.split('?')[0].endsWith(ext));
            if (!isFile) continue;

            scannedUrls.add(href);

            // Don't re-badge
            if (link.querySelector('.phishguard-badge')) continue;

            // Show scanning badge
            const scanBadge = createBadge('scanning', 'SCANNING', null, null);
            link.style.position = link.style.position || 'relative';
            link.appendChild(scanBadge);

            // Analyze via background
            try {
                const response = await new Promise((resolve, reject) => {
                    chrome.runtime.sendMessage(
                        { action: 'analyzeUrl', data: { url: link.href } },
                        (resp) => {
                            if (chrome.runtime.lastError) {
                                reject(new Error(chrome.runtime.lastError.message));
                            } else {
                                resolve(resp);
                            }
                        }
                    );
                });

                scanBadge.remove();

                if (response?.success && response.data) {
                    const r = response.data;
                    const type = r.risk_level === 'HIGH' ? 'danger'
                               : r.risk_level === 'MEDIUM' ? 'warning'
                               : 'safe';
                    const label = r.risk_level === 'HIGH' ? `DANGER ${r.confidence}%`
                                : r.risk_level === 'MEDIUM' ? `CAUTION ${r.confidence}%`
                                : 'SAFE';
                    link.appendChild(createBadge(type, label, r, link.href));
                }
            } catch (e) {
                scanBadge.remove();
            }
        }
    }

    // ─── Scan Images on Page ────────────────────────────────────────
    async function scanImages() {
        const images = document.querySelectorAll('img[src]');
        let scanned = 0;
        const MAX_IMAGES = 5;

        for (const img of images) {
            if (scanned >= MAX_IMAGES) break;

            const src = img.src?.toLowerCase() || '';
            if (!src.startsWith('http')) continue;

            if (img.naturalWidth < 200 || img.naturalHeight < 100) continue;

            if (img.dataset.phishguardScanned) continue;
            img.dataset.phishguardScanned = 'true';
            scanned++;

            try {
                const response = await new Promise((resolve, reject) => {
                    chrome.runtime.sendMessage(
                        { action: 'analyzeImage', data: { imageUrl: img.src } },
                        (resp) => {
                            if (chrome.runtime.lastError) {
                                reject(new Error(chrome.runtime.lastError.message));
                            } else {
                                resolve(resp);
                            }
                        }
                    );
                });

                if (response?.success && response.data && response.data.confidence > 30) {
                    const r = response.data;
                    const wrapper = document.createElement('div');
                    wrapper.style.cssText = 'position:relative; display:inline-block;';
                    img.parentNode.insertBefore(wrapper, img);
                    wrapper.appendChild(img);

                    const isHigh = r.risk_level === 'HIGH';
                    const overlay = document.createElement('div');
                    overlay.className = 'phishguard-badge-clickable';
                    overlay.style.cssText = `
                        position: absolute; top: 4px; right: 4px;
                        padding: 4px 10px;
                        font-size: 10px; font-weight: bold;
                        font-family: system-ui, sans-serif;
                        color: ${isHigh ? '#ff3333' : '#FFB300'};
                        background: rgba(0,0,0,0.85);
                        border: 1px solid ${isHigh ? '#ff3333' : '#FFB300'};
                        border-radius: 4px;
                        z-index: 99999;
                        cursor: pointer;
                        transition: all 0.2s;
                    `;
                    overlay.textContent = `⚠ ${r.prediction} (${r.confidence}%) — Click for details`;

                    overlay.addEventListener('click', (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        showDetailModal(r, img.src);
                    });

                    wrapper.appendChild(overlay);
                }
            } catch (e) {
                // Silent fail
            }
        }
    }

    // ─── Auto-detect Page Text (Messages) ───────────────────────────
    async function scanPageText() {
        const pageText = document.body.innerText;
        if (!pageText || pageText.length < 50) return;

        try {
            chrome.runtime.sendMessage(
                { action: 'analyzeText', data: { text: pageText.substring(0, 5000) } },
                (response) => {
                    if (response?.success && response.data && response.data.risk_level !== 'LOW') {
                        chrome.storage.local.set({
                            pageTextResult: {
                                result: response.data,
                                url: window.location.href,
                                timestamp: Date.now(),
                            }
                        });
                    }
                }
            );
        } catch (e) {
            // Silent fail
        }
    }

    // ─── Run scans after page load ──────────────────────────────────
    function runScans() {
        setTimeout(scanFileLinks, 1000);
        setTimeout(scanImages, 3000);
        setTimeout(scanPageText, 2000);
    }

    if (document.readyState === 'complete') {
        runScans();
    } else {
        window.addEventListener('load', runScans);
    }

    // Watch for dynamically added content
    const observer = new MutationObserver((mutations) => {
        let hasNewLinks = false;
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (node.nodeType === 1 && (node.tagName === 'A' || node.querySelector?.('a'))) {
                    hasNewLinks = true;
                    break;
                }
            }
            if (hasNewLinks) break;
        }
        if (hasNewLinks) {
            setTimeout(scanFileLinks, 500);
        }
    });

    observer.observe(document.body, { childList: true, subtree: true });

})();
