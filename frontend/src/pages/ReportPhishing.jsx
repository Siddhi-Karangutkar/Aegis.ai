import React, { useState, useEffect, useRef } from 'react';
import PageLayout from '../components/PageLayout';
import { UploadCloud, Shield, AlertTriangle, CheckCircle, XCircle, Search, FileText, Mail, MessageSquare, Link2, Activity, Zap, Eye, Brain } from 'lucide-react';

// ─── Groq AI Integration ───────────────────────────────────────────
const callGroqAI = async (prompt) => {
    const apiKey = import.meta.env.VITE_GROQ_API_KEY;
    if (!apiKey || apiKey === 'your_groq_api_key_here') {
        return null; // Fallback to local generation
    }
    try {
        const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'llama-3.3-70b-versatile',
                messages: [{ role: 'user', content: prompt }],
                max_tokens: 500,
                temperature: 0.3
            })
        });
        const data = await res.json();
        return data.choices?.[0]?.message?.content || null;
    } catch {
        return null;
    }
};

// ─── SVG Circular Gauge Component ──────────────────────────────────
const CircularGauge = ({ value, label, colorScheme = 'risk' }) => {
    const [animatedValue, setAnimatedValue] = useState(0);
    const radius = 70;
    const circumference = 2 * Math.PI * radius;
    const percentage = Math.round(animatedValue * 100);

    useEffect(() => {
        let start = 0;
        const duration = 1200;
        const startTime = Date.now();
        const animate = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // Ease-out cubic
            const eased = 1 - Math.pow(1 - progress, 3);
            setAnimatedValue(value * eased);
            if (progress < 1) requestAnimationFrame(animate);
        };
        animate();
    }, [value]);

    const getColor = () => {
        if (colorScheme === 'confidence') return '#00f0ff';
        if (percentage >= 75) return '#ff3333';
        if (percentage >= 45) return '#FFB300';
        return '#00ff88';
    };

    const offset = circumference - (animatedValue * circumference);
    const color = getColor();

    return (
        <div style={gaugeStyles.container}>
            <svg width="200" height="200" viewBox="0 0 200 200">
                {/* Background Ring */}
                <circle cx="100" cy="100" r={radius} fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="12" />
                
                {/* Progress Ring */}
                <circle
                    cx="100" cy="100" r={radius} fill="none"
                    stroke={color} strokeWidth="12" strokeLinecap="round"
                    strokeDasharray={circumference} strokeDashoffset={offset}
                    transform="rotate(-90 100 100)"
                    style={{ 
                        transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1)', 
                        filter: `drop-shadow(0 0 12px ${color}80)` 
                    }}
                />

                {/* Score Text */}
                <text x="100" y="95" textAnchor="middle" fill={color} fontSize="42" fontFamily="Orbitron, sans-serif" fontWeight="900" style={{ filter: `drop-shadow(0 0 8px ${color}40)` }}>
                    {percentage}%
                </text>

                {/* Label Text */}
                <text x="100" y="125" textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="10" fontFamily="Orbitron, sans-serif" letterSpacing="3px" fontWeight="700">
                    {label}
                </text>
            </svg>
        </div>
    );
};

const gaugeStyles = {
    container: {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
    }
};

// ─── Verdict Banner ────────────────────────────────────────────────
const VerdictBanner = ({ verdict }) => {
    const config = {
        malicious: { color: '#ff3333', bg: 'rgba(255,51,51,0.1)', border: 'rgba(255,51,51,0.3)', icon: <XCircle size={28} />, label: 'MALICIOUS THREAT DETECTED' },
        suspicious: { color: '#FFB300', bg: 'rgba(255,179,0,0.1)', border: 'rgba(255,179,0,0.3)', icon: <AlertTriangle size={28} />, label: 'SUSPICIOUS ACTIVITY FLAGGED' },
        benign: { color: '#00ff88', bg: 'rgba(0,255,136,0.1)', border: 'rgba(0,255,136,0.3)', icon: <CheckCircle size={28} />, label: 'CONTENT APPEARS SAFE' },
    };
    const c = config[verdict] || config.benign;

    return (
        <div style={{
            display: 'flex', alignItems: 'center', gap: '1rem', padding: '1.2rem 2rem',
            background: c.bg, border: `1px solid ${c.border}`, borderRadius: '12px',
            color: c.color, fontFamily: 'Orbitron, sans-serif', fontSize: '0.95rem',
            fontWeight: 700, letterSpacing: '2px', marginBottom: '1.5rem',
            boxShadow: `0 0 20px ${c.color}20`, backdropFilter: 'blur(12px)',
        }}>
            {c.icon} {c.label}
        </div>
    );
};

// ─── Breakdown Bar Chart ───────────────────────────────────────────
const BreakdownChart = ({ breakdown }) => {
    const bars = [
        { label: 'Text Analysis', value: breakdown.text_score, color: '#00f0ff' },
        { label: 'URL Analysis', value: breakdown.url_score, color: '#7000FF' },
        { label: 'Rule Engine', value: breakdown.rule_score, color: '#FFB300' },
    ];
    return (
        <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
            <h3 style={{ color: '#00f0ff', fontSize: '0.85rem', marginBottom: '1.2rem', fontFamily: 'Orbitron, sans-serif', letterSpacing: '2px' }}>
                <Activity size={16} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
                SCORE BREAKDOWN
            </h3>
            {bars.map((bar, i) => (
                <div key={i} style={{ marginBottom: '1rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                        <span style={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.8rem', fontFamily: 'monospace' }}>{bar.label}</span>
                        <span style={{ color: bar.color, fontFamily: 'Orbitron, sans-serif', fontSize: '0.8rem' }}>{Math.round(bar.value * 100)}%</span>
                    </div>
                    <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: '6px', height: '8px', overflow: 'hidden' }}>
                        <div style={{
                            width: `${bar.value * 100}%`, height: '100%', borderRadius: '6px',
                            background: `linear-gradient(90deg, ${bar.color}80, ${bar.color})`,
                            transition: 'width 1.2s cubic-bezier(0.4, 0, 0.2, 1)',
                            boxShadow: `0 0 10px ${bar.color}40`
                        }} />
                    </div>
                </div>
            ))}
        </div>
    );
};

// ─── Reason Cards (Suspicious Word Highlighting) ───────────────────
const ReasonCards = ({ reasons }) => (
    <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h3 style={{ color: '#ff3333', fontSize: '0.85rem', marginBottom: '1.2rem', fontFamily: 'Orbitron, sans-serif', letterSpacing: '2px' }}>
            <Eye size={16} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
            THREAT INDICATORS
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.7rem' }}>
            {reasons.map((reason, i) => (
                <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: '0.8rem', padding: '0.8rem 1rem',
                    background: 'rgba(255,51,51,0.05)', border: '1px solid rgba(255,51,51,0.15)',
                    borderRadius: '8px', fontSize: '0.85rem', color: 'rgba(255,255,255,0.85)',
                    fontFamily: 'monospace'
                }}>
                    <AlertTriangle size={14} color="#FFB300" style={{ flexShrink: 0 }} />
                    {reason}
                </div>
            ))}
        </div>
    </div>
);

// ─── AI Explanation Card ───────────────────────────────────────────
const AIExplanationCard = ({ explanation, loading }) => (
    <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h3 style={{ color: '#7000FF', fontSize: '0.85rem', marginBottom: '1rem', fontFamily: 'Orbitron, sans-serif', letterSpacing: '2px' }}>
            <Brain size={16} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
            AI THREAT ANALYSIS
        </h3>
        {loading ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.8rem', color: 'rgba(255,255,255,0.5)', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                <div className="pulse-dot" /> Generating AI analysis...
            </div>
        ) : (
            <p style={{ color: 'rgba(255,255,255,0.8)', fontSize: '0.9rem', lineHeight: 1.7, fontFamily: 'Inter, sans-serif' }}>
                {explanation}
            </p>
        )}
    </div>
);

// ─── Recommended Actions ───────────────────────────────────────────
const RecommendedActions = ({ verdict, aiRecommendation, loading }) => {
    const localActions = {
        malicious: [
            { icon: <XCircle size={18} />, text: 'Do NOT click any links or download attachments from this source', color: '#ff3333' },
            { icon: <Shield size={18} />, text: 'Report this to your IT security team immediately', color: '#ff3333' },
            { icon: <AlertTriangle size={18} />, text: 'Mark as spam/phishing in your email client', color: '#FFB300' },
            { icon: <Zap size={18} />, text: 'Change your password if you accidentally interacted', color: '#FFB300' },
        ],
        suspicious: [
            { icon: <AlertTriangle size={18} />, text: 'Exercise caution — verify the sender through a separate channel', color: '#FFB300' },
            { icon: <Search size={18} />, text: 'Hover over links to check the actual destination URL', color: '#FFB300' },
            { icon: <Shield size={18} />, text: 'Do not share personal information until verified', color: '#00f0ff' },
        ],
        benign: [
            { icon: <CheckCircle size={18} />, text: 'This content appears safe based on our analysis', color: '#00ff88' },
            { icon: <Shield size={18} />, text: 'Always remain vigilant — no detection system is 100% perfect', color: '#00f0ff' },
        ],
    };

    const actions = localActions[verdict] || localActions.benign;

    return (
        <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
            <h3 style={{ color: '#00ff88', fontSize: '0.85rem', marginBottom: '1.2rem', fontFamily: 'Orbitron, sans-serif', letterSpacing: '2px' }}>
                <Zap size={16} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
                RECOMMENDED ACTIONS
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.7rem' }}>
                {actions.map((action, i) => (
                    <div key={i} style={{
                        display: 'flex', alignItems: 'center', gap: '0.8rem', padding: '0.8rem 1rem',
                        background: `${action.color}08`, border: `1px solid ${action.color}20`,
                        borderRadius: '8px', color: 'rgba(255,255,255,0.85)', fontSize: '0.85rem'
                    }}>
                        <span style={{ color: action.color, flexShrink: 0 }}>{action.icon}</span>
                        {action.text}
                    </div>
                ))}
            </div>
            {loading && (
                <div style={{ marginTop: '1rem', color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                    <div className="pulse-dot" style={{ display: 'inline-block', marginRight: '8px' }} /> Loading AI recommendations...
                </div>
            )}
            {aiRecommendation && (
                <div style={{ marginTop: '1rem', padding: '1rem', background: 'rgba(0,240,255,0.05)', border: '1px solid rgba(0,240,255,0.15)', borderRadius: '8px' }}>
                    <span style={{ color: '#00f0ff', fontSize: '0.75rem', fontFamily: 'Orbitron, sans-serif', letterSpacing: '1px' }}>AI RECOMMENDATION</span>
                    <p style={{ color: 'rgba(255,255,255,0.8)', fontSize: '0.85rem', lineHeight: 1.6, marginTop: '0.5rem' }}>{aiRecommendation}</p>
                </div>
            )}
        </div>
    );
};

// ─── Threat Intelligence Panel ─────────────────────────────────────
const ThreatIntelPanel = ({ result, scanType }) => (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h3 style={{ color: '#00f0ff', fontSize: '0.85rem', marginBottom: '1.2rem', fontFamily: 'Orbitron, sans-serif', letterSpacing: '2px' }}>
            <Shield size={16} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
            THREAT INTELLIGENCE SUMMARY
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            {[
                { label: 'Scan Type', value: scanType },
                { label: 'Verdict', value: result.verdict?.toUpperCase() },
                { label: 'Confidence', value: `${Math.round(result.confidence_score * 100)}%` },
                { label: 'Indicators Found', value: result.reasons?.length || 0 },
                { label: 'Text Risk', value: `${Math.round((result.breakdown?.text_score || 0) * 100)}%` },
                { label: 'URL Risk', value: `${Math.round((result.breakdown?.url_score || 0) * 100)}%` },
            ].map((item, i) => (
                <div key={i} style={{ padding: '0.8rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                    <div style={{ fontSize: '0.65rem', color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '0.3rem' }}>{item.label}</div>
                    <div style={{ fontSize: '1rem', color: '#fff', fontFamily: 'Orbitron, sans-serif', fontWeight: 700 }}>{item.value}</div>
                </div>
            ))}
        </div>
    </div>
);


// ═══════════════════════════════════════════════════════════════════
// ─── MAIN DASHBOARD COMPONENT ─────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════
const SCAN_TYPES = [
    { id: 'email', label: 'Email Text Scanner', icon: <Mail size={18} />, description: 'Analyze email body text for phishing patterns' },
    { id: 'url', label: 'URL Scanner', icon: <Link2 size={18} />, description: 'Scan URLs for malicious indicators' },
    { id: 'file', label: 'File / Attachment Scanner', icon: <FileText size={18} />, description: 'Upload PDF attachments for sandbox analysis' },
    { id: 'message', label: 'Suspicious Message Scanner', icon: <MessageSquare size={18} />, description: 'Paste any suspicious text message for analysis' },
];

const ReportPhishing = () => {
    const [scanType, setScanType] = useState('email');
    const [emailText, setEmailText] = useState('');
    const [urlInput, setUrlInput] = useState('');
    const [messageText, setMessageText] = useState('');
    const [file, setFile] = useState(null);
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [result, setResult] = useState(null);
    const [aiExplanation, setAiExplanation] = useState('');
    const [aiRecommendation, setAiRecommendation] = useState('');
    const [aiLoading, setAiLoading] = useState(false);
    const [error, setError] = useState('');
    const fileInputRef = useRef(null);

    // ─── Generate local AI explanation (Groq fallback) ────────────
    const generateLocalExplanation = (res) => {
        const verdictMap = { malicious: 'a high-risk phishing attempt', suspicious: 'potentially suspicious content', benign: 'likely safe content' };
        const score = Math.round(res.confidence_score * 100);
        let explanation = `Aegis.ai has classified this input as ${verdictMap[res.verdict] || 'unknown'} with a confidence of ${score}%. `;
        if (res.reasons?.length > 0) {
            explanation += `Key indicators include: ${res.reasons.join('; ')}. `;
        }
        if (res.breakdown) {
            const { text_score, url_score, rule_score } = res.breakdown;
            explanation += `The analysis breakdown shows text risk at ${Math.round(text_score * 100)}%, URL risk at ${Math.round(url_score * 100)}%, and rule-based detection at ${Math.round(rule_score * 100)}%.`;
        }
        return explanation;
    };

    // ─── Call Groq for AI explanations ────────────────────────────
    const fetchAIInsights = async (res, inputSummary) => {
        setAiLoading(true);
        const prompt = `You are Aegis.AI, a cybersecurity phishing detection engine. Analyze this result and provide a concise, non-technical explanation for the user.

Detection Result:
- Verdict: ${res.verdict}
- Confidence: ${Math.round(res.confidence_score * 100)}%
- Indicators: ${res.reasons?.join(', ') || 'None'}
- Breakdown: Text=${Math.round((res.breakdown?.text_score||0)*100)}%, URL=${Math.round((res.breakdown?.url_score||0)*100)}%, Rule=${Math.round((res.breakdown?.rule_score||0)*100)}%

Input analyzed: "${inputSummary?.substring(0, 200)}"

Provide:
1. A 2-3 sentence plain English explanation of why this was flagged (or not).
2. DO NOT use markdown formatting.`;

        const recPrompt = `You are Aegis.AI. Based on this phishing scan result, give 2-3 specific, actionable security recommendations in plain text. No markdown.
Verdict: ${res.verdict}, Confidence: ${Math.round(res.confidence_score * 100)}%, Indicators: ${res.reasons?.join(', ')}`;

        const [explanation, recommendation] = await Promise.all([
            callGroqAI(prompt),
            callGroqAI(recPrompt)
        ]);

        setAiExplanation(explanation || generateLocalExplanation(res));
        setAiRecommendation(recommendation || '');
        setAiLoading(false);
    };

    // ─── Submit to Backend ────────────────────────────────────────
    const handleAnalyze = async () => {
        setError('');
        setResult(null);
        setAiExplanation('');
        setAiRecommendation('');
        setIsAnalyzing(true);

        try {
            const formData = new FormData();
            let inputSummary = '';

            switch (scanType) {
                case 'email':
                    if (!emailText.trim()) { setError('Please enter email text to analyze.'); setIsAnalyzing(false); return; }
                    formData.append('email_text', emailText);
                    inputSummary = emailText;
                    break;
                case 'url':
                    if (!urlInput.trim()) { setError('Please enter a URL to analyze.'); setIsAnalyzing(false); return; }
                    formData.append('urls', urlInput.trim());
                    inputSummary = urlInput;
                    break;
                case 'file':
                    if (!file) { setError('Please upload a file to analyze.'); setIsAnalyzing(false); return; }
                    formData.append('attachments', file);
                    inputSummary = `File: ${file.name}`;
                    break;
                case 'message':
                    if (!messageText.trim()) { setError('Please enter a message to analyze.'); setIsAnalyzing(false); return; }
                    formData.append('email_text', messageText);
                    inputSummary = messageText;
                    break;
            }

            const response = await fetch('/api/detect/', {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.error || `Server returned ${response.status}`);
            }

            const data = await response.json();
            setResult(data);
            setIsAnalyzing(false);

            // Fetch AI insights (non-blocking)
            fetchAIInsights(data, inputSummary);

        } catch (err) {
            setError(err.message || 'Failed to connect to the Aegis.ai backend. Is the server running?');
            setIsAnalyzing(false);
        }
    };

    const resetDashboard = () => {
        setResult(null);
        setAiExplanation('');
        setAiRecommendation('');
        setError('');
        setEmailText(''); setUrlInput(''); setMessageText('');
        setFile(null);
    };

    const currentScan = SCAN_TYPES.find(s => s.id === scanType);

    return (
        <PageLayout
            title="Threat Detection Dashboard"
            subtitle="Aegis.ai Neural Phishing Detection Engine — Analyze threats in real-time"
        >
            {/* Scanner Type Selector */}
            <div style={styles.selectorRow}>
                {SCAN_TYPES.map(s => (
                    <button
                        key={s.id}
                        onClick={() => { setScanType(s.id); setResult(null); setError(''); }}
                        className="glass-panel"
                        style={{
                            ...styles.selectorBtn,
                            borderColor: scanType === s.id ? '#00f0ff' : 'rgba(255,255,255,0.08)',
                            background: scanType === s.id ? 'rgba(0,240,255,0.08)' : 'rgba(16,24,39,0.6)',
                            color: scanType === s.id ? '#00f0ff' : 'rgba(255,255,255,0.5)',
                        }}
                    >
                        {s.icon}
                        <span style={{ fontSize: '0.75rem', fontFamily: 'Orbitron, sans-serif', letterSpacing: '1px' }}>{s.label}</span>
                    </button>
                ))}
            </div>

            <div style={styles.dashboardGrid}>
                {/* ─── LEFT: Input Panel ────────────────────────────── */}
                <div className="glass-panel" style={styles.inputPanel}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.8rem', marginBottom: '1.5rem' }}>
                        {currentScan.icon}
                        <div>
                            <h3 style={{ color: '#00f0ff', fontSize: '0.9rem', fontFamily: 'Orbitron, sans-serif' }}>{currentScan.label}</h3>
                            <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.75rem', fontFamily: 'monospace' }}>{currentScan.description}</p>
                        </div>
                    </div>

                    {/* Email Scanner */}
                    {scanType === 'email' && (
                        <div style={styles.formStack}>
                            <div style={styles.fieldGroup}>
                                <label style={styles.label}>Email Body / Header *</label>
                                <textarea value={emailText} onChange={e => setEmailText(e.target.value)}
                                    placeholder="Paste the complete email body or raw headers here..."
                                    style={styles.textarea} />
                            </div>
                        </div>
                    )}

                    {/* URL Scanner */}
                    {scanType === 'url' && (
                        <div style={styles.formStack}>
                            <div style={styles.fieldGroup}>
                                <label style={styles.label}>Suspicious URL *</label>
                                <input type="text" value={urlInput} onChange={e => setUrlInput(e.target.value)}
                                    placeholder="e.g. http://verify-paypal-login-secure.com/auth"
                                    style={styles.input} />
                            </div>
                            <div style={{ padding: '1rem', background: 'rgba(0,240,255,0.03)', borderRadius: '8px', border: '1px solid rgba(0,240,255,0.1)' }}>
                                <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: '0.8rem', fontFamily: 'monospace' }}>
                                    <Link2 size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
                                    Real-Time URL Analyzer: The engine will check for suspicious length, IP addresses, excessive subdomains, and keyword patterns.
                                </p>
                            </div>
                        </div>
                    )}

                    {/* File Scanner */}
                    {scanType === 'file' && (
                        <div style={styles.formStack}>
                            <div style={styles.fieldGroup}>
                                <label style={styles.label}>Upload Attachment (PDF) *</label>
                                <div
                                    onClick={() => fileInputRef.current?.click()}
                                    style={{
                                        ...styles.dropzone,
                                        borderColor: file ? '#00ff88' : 'rgba(0,210,255,0.3)',
                                        background: file ? 'rgba(0,255,136,0.03)' : 'rgba(0,210,255,0.02)',
                                    }}
                                >
                                    <UploadCloud size={36} color={file ? '#00ff88' : '#00f0ff'} />
                                    <p style={{ color: file ? '#00ff88' : 'rgba(255,255,255,0.5)', marginTop: '0.8rem', fontSize: '0.85rem' }}>
                                        {file ? `✓ ${file.name}` : 'Click to upload or drag & drop PDF'}
                                    </p>
                                    <input ref={fileInputRef} type="file" accept=".pdf" hidden
                                        onChange={e => setFile(e.target.files[0])} />
                                </div>
                            </div>
                            <div style={{ padding: '1rem', background: 'rgba(112,0,255,0.03)', borderRadius: '8px', border: '1px solid rgba(112,0,255,0.15)' }}>
                                <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: '0.8rem', fontFamily: 'monospace' }}>
                                    <FileText size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
                                    Sandbox Scanner: PDFs are analyzed for embedded text, hidden URLs, and social engineering patterns.
                                </p>
                            </div>
                        </div>
                    )}

                    {/* Message Scanner */}
                    {scanType === 'message' && (
                        <div style={styles.formStack}>
                            <div style={styles.fieldGroup}>
                                <label style={styles.label}>Suspicious Message Text *</label>
                                <textarea value={messageText} onChange={e => setMessageText(e.target.value)}
                                    placeholder="Paste the suspicious SMS, WhatsApp, or any text message here..."
                                    style={styles.textarea} />
                            </div>
                        </div>
                    )}

                    {/* Error Display */}
                    {error && (
                        <div style={{ padding: '1rem', background: 'rgba(255,51,51,0.08)', border: '1px solid rgba(255,51,51,0.2)', borderRadius: '8px', marginTop: '1rem', color: '#ff3333', fontSize: '0.85rem', fontFamily: 'monospace' }}>
                            ⚠ {error}
                        </div>
                    )}

                    {/* Action Buttons */}
                    <div style={{ display: 'flex', gap: '1rem', marginTop: '1.5rem' }}>
                        <button
                            onClick={handleAnalyze}
                            disabled={isAnalyzing}
                            className="btn btn-primary"
                            style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', opacity: isAnalyzing ? 0.6 : 1 }}
                        >
                            {isAnalyzing ? (
                                <><div className="spinner" /> ANALYZING...</>
                            ) : (
                                <><Search size={18} /> ANALYZE THREAT</>
                            )}
                        </button>
                        {result && (
                            <button onClick={resetDashboard} className="btn" style={{ border: '1px solid rgba(255,255,255,0.15)', color: 'rgba(255,255,255,0.6)' }}>
                                RESET
                            </button>
                        )}
                    </div>
                </div>

                {/* ─── RIGHT: Results Panel ─────────────────────────── */}
                <div style={styles.resultsPanel}>
                    {!result && !isAnalyzing && (
                        <div className="glass-panel" style={{ padding: '4rem 2rem', textAlign: 'center', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
                            <Shield size={64} color="rgba(0,240,255,0.15)" />
                            <h3 style={{ color: 'rgba(255,255,255,0.2)', fontFamily: 'Orbitron, sans-serif', fontSize: '1.1rem', marginTop: '1.5rem' }}>AWAITING INPUT</h3>
                            <p style={{ color: 'rgba(255,255,255,0.1)', fontFamily: 'monospace', marginTop: '0.5rem', fontSize: '0.8rem' }}>Submit content to initialize threat analysis</p>
                        </div>
                    )}

                    {isAnalyzing && (
                        <div className="glass-panel" style={{ padding: '4rem 2rem', textAlign: 'center', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
                            <div className="spinner-large" />
                            <h3 style={{ color: '#00f0ff', fontFamily: 'Orbitron, sans-serif', fontSize: '1rem', marginTop: '2rem', letterSpacing: '2px' }}>ANALYZING PAYLOAD</h3>
                            <p style={{ color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', marginTop: '0.5rem', fontSize: '0.8rem' }}>Running neural detection engine...</p>
                        </div>
                    )}

                    {result && (
                        <>
                            <VerdictBanner verdict={result.verdict} />

                            {/* Gauge Row */}
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '1.5rem' }}>
                                <div className="glass-panel" style={{ padding: '1.5rem', textAlign: 'center' }}>
                                    {/* Risk Score: Directly the threat probability */}
                                    <CircularGauge value={result.confidence_score} label="RISK SCORE" colorScheme="risk" />
                                </div>
                                <div className="glass-panel" style={{ padding: '1.5rem', textAlign: 'center' }}>
                                    {/* Confidence: Calculated as model's distance from the 50/50 threshold */}
                                    {/* Higher distance from 0.5 = higher model certainty */}
                                    <CircularGauge 
                                        value={Math.min(1.0, Math.abs(result.confidence_score - 0.5) * 2 + 0.1)} 
                                        label="CONFIDENCE" 
                                        colorScheme="confidence" 
                                    />
                                </div>
                            </div>

                            {/* Breakdown */}
                            {result.breakdown && <BreakdownChart breakdown={result.breakdown} />}

                            {/* Threat Indicators */}
                            {result.reasons?.length > 0 && <ReasonCards reasons={result.reasons} />}

                            {/* AI Explanation */}
                            <AIExplanationCard explanation={aiExplanation} loading={aiLoading && !aiExplanation} />

                            {/* Recommended Actions */}
                            <RecommendedActions verdict={result.verdict} aiRecommendation={aiRecommendation} loading={aiLoading && !aiRecommendation} />

                            {/* Threat Intel Summary */}
                            <ThreatIntelPanel result={result} scanType={currentScan.label} />
                        </>
                    )}
                </div>
            </div>
        </PageLayout>
    );
};

// ─── Styles ────────────────────────────────────────────────────────
const styles = {
    selectorRow: {
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '1rem',
        marginBottom: '2rem',
    },
    selectorBtn: {
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.6rem',
        padding: '1.2rem 0.8rem', borderRadius: '12px', border: '1px solid',
        cursor: 'pointer', transition: 'all 0.3s ease', backdropFilter: 'blur(12px)',
    },
    dashboardGrid: {
        display: 'grid',
        gridTemplateColumns: '380px 1fr',
        gap: '2rem',
        alignItems: 'flex-start',
    },
    inputPanel: {
        padding: '2rem',
        position: 'sticky',
        top: '2rem',
    },
    resultsPanel: {
        minHeight: '500px',
    },
    formStack: {
        display: 'flex', flexDirection: 'column', gap: '1.2rem',
    },
    fieldGroup: {
        display: 'flex', flexDirection: 'column', gap: '0.5rem',
    },
    label: {
        color: '#00f0ff', fontWeight: 600, fontSize: '0.8rem',
        fontFamily: 'Orbitron, sans-serif', letterSpacing: '1px',
    },
    input: {
        padding: '0.9rem 1rem', background: 'rgba(0,0,0,0.3)',
        border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px',
        color: 'white', fontSize: '0.9rem', outline: 'none',
        transition: 'border-color 0.3s', fontFamily: 'monospace',
    },
    textarea: {
        padding: '0.9rem 1rem', background: 'rgba(0,0,0,0.3)',
        border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px',
        color: 'white', fontSize: '0.9rem', minHeight: '150px',
        resize: 'vertical', outline: 'none', transition: 'border-color 0.3s',
        fontFamily: 'monospace',
    },
    dropzone: {
        padding: '3rem', border: '2px dashed', borderRadius: '12px',
        textAlign: 'center', cursor: 'pointer', transition: 'all 0.3s',
        display: 'flex', flexDirection: 'column', alignItems: 'center',
    },
};

// ─── Injected CSS (animations, focus states, spinner) ─────────────
const dashboardCSS = `
    input:focus, textarea:focus {
        border-color: #00f0ff !important;
        box-shadow: 0 0 15px rgba(0,240,255,0.1) !important;
    }
    .spinner {
        width: 18px; height: 18px; border: 2px solid transparent;
        border-top-color: #00f0ff; border-radius: 50%;
        animation: spin 0.8s linear infinite;
    }
    .spinner-large {
        width: 48px; height: 48px; border: 3px solid rgba(255,255,255,0.05);
        border-top-color: #00f0ff; border-radius: 50%;
        animation: spin 1s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .pulse-dot {
        width: 8px; height: 8px; border-radius: 50%;
        background: #00f0ff; display: inline-block;
        animation: pulse 1.2s ease-in-out infinite;
    }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
    @media (max-width: 900px) {
        .dashboard-grid-override { grid-template-columns: 1fr !important; }
    }
`;
if (typeof document !== 'undefined') {
    const s = document.createElement('style');
    s.innerText = dashboardCSS;
    document.head.appendChild(s);
}

export default ReportPhishing;
