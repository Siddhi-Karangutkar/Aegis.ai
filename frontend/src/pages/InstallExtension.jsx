import React from 'react';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';

const InstallExtension = () => {
    const apiUrl = window.location.origin;

    return (
        <>
            <Navbar />
            <div style={styles.page}>
                <div style={styles.container}>
                    <h1 style={styles.title}>🛡️ Install PhishGuard</h1>
                    <p style={styles.subtitle}>
                        Get real-time AI phishing protection in your browser in under 60 seconds.
                    </p>

                    <div style={styles.downloadSection}>
                        <a href="/download-extension/" style={styles.downloadBtn}>
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#02043b" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                                <polyline points="7 10 12 15 17 10" />
                                <line x1="12" y1="15" x2="12" y2="3" />
                            </svg>
                            Download PhishGuard Extension
                        </a>
                        <p style={styles.autoConfig}>
                            ✓ Pre-configured to connect to <code style={styles.code}>{apiUrl}</code> automatically
                        </p>
                    </div>

                    <div style={styles.steps}>
                        {[
                            {
                                num: '1',
                                title: 'Unzip the File',
                                desc: <>Extract <code style={styles.code}>PhishGuard-Extension.zip</code> to any folder on your computer. You'll get a folder named <code style={styles.code}>PhishGuard</code>.</>
                            },
                            {
                                num: '2',
                                title: 'Open Chrome Extensions',
                                desc: <>Type <code style={styles.code}>chrome://extensions</code> in your Chrome address bar and press Enter. Then toggle <strong>Developer Mode</strong> ON in the top-right corner.</>
                            },
                            {
                                num: '3',
                                title: 'Load the Extension',
                                desc: <>Click <strong>"Load unpacked"</strong> in the top-left. Navigate to and select the <code style={styles.code}>PhishGuard</code> folder you extracted.</>
                            },
                            {
                                num: '4',
                                title: 'Pin It & Go!',
                                desc: <>Click the 🧩 puzzle icon in Chrome's toolbar, then click the 📌 pin next to <strong>PhishGuard</strong> so you can always see it.</>
                            }
                        ].map((step, idx) => (
                            <div key={idx} style={styles.step}>
                                <div style={styles.stepNumber}>{step.num}</div>
                                <div style={styles.stepContent}>
                                    <h3 style={styles.stepTitle}>{step.title}</h3>
                                    <p style={styles.stepDesc}>{step.desc}</p>
                                </div>
                            </div>
                        ))}
                    </div>

                    <div style={styles.doneSection}>
                        <h2 style={styles.doneTitle}>🎉 You're Protected!</h2>
                        <p style={styles.doneText}>
                            PhishGuard is now scanning every page you visit, every link you click, and every file you download.
                            Malicious content will be blocked in real-time using our AI engine and Docker isolation sandbox.
                        </p>
                    </div>
                </div>
            </div>
            <Footer />
        </>
    );
};

const styles = {
    page: {
        minHeight: '100vh',
        paddingTop: '100px',
    },
    container: {
        maxWidth: '900px',
        margin: '0 auto',
        padding: '2rem',
    },
    title: {
        fontFamily: 'Orbitron, sans-serif',
        fontSize: '2.8rem',
        textAlign: 'center',
        marginBottom: '0.5rem',
        color: '#00d2ff',
    },
    subtitle: {
        textAlign: 'center',
        color: 'rgba(255,255,255,0.7)',
        fontSize: '1.1rem',
        marginBottom: '3rem',
    },
    downloadSection: {
        textAlign: 'center',
        marginBottom: '4rem',
    },
    downloadBtn: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '12px',
        padding: '1.2rem 3rem',
        background: 'linear-gradient(135deg, #00d2ff, #00ff9d)',
        color: '#02043b',
        fontFamily: 'Orbitron, sans-serif',
        fontWeight: 700,
        fontSize: '1.1rem',
        border: 'none',
        borderRadius: '12px',
        cursor: 'pointer',
        textDecoration: 'none',
        boxShadow: '0 0 30px rgba(0, 210, 255, 0.3)',
        transition: 'all 0.3s ease',
    },
    autoConfig: {
        marginTop: '1rem',
        color: '#00ff9d',
        fontSize: '0.9rem',
    },
    code: {
        background: 'rgba(0, 210, 255, 0.1)',
        color: '#00d2ff',
        padding: '2px 8px',
        borderRadius: '4px',
        fontSize: '0.9rem',
    },
    steps: {
        display: 'flex',
        flexDirection: 'column',
        gap: '1.5rem',
    },
    step: {
        display: 'flex',
        gap: '1.5rem',
        padding: '2rem',
        background: 'rgba(10, 14, 23, 0.6)',
        backdropFilter: 'blur(12px)',
        border: '1px solid rgba(0, 210, 255, 0.15)',
        borderRadius: '16px',
        transition: 'all 0.3s ease',
    },
    stepNumber: {
        flexShrink: 0,
        width: '50px',
        height: '50px',
        background: '#00d2ff',
        color: '#02043b',
        fontFamily: 'Orbitron, sans-serif',
        fontWeight: 700,
        fontSize: '1.4rem',
        borderRadius: '50%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
    },
    stepContent: {
        flex: 1,
    },
    stepTitle: {
        fontFamily: 'Orbitron, sans-serif',
        fontSize: '1.2rem',
        color: '#00d2ff',
        marginBottom: '0.5rem',
    },
    stepDesc: {
        color: 'rgba(255,255,255,0.7)',
        fontSize: '0.95rem',
        lineHeight: 1.6,
    },
    doneSection: {
        textAlign: 'center',
        padding: '3rem 2rem',
        marginTop: '2rem',
        background: 'rgba(10, 14, 23, 0.6)',
        border: '1px solid #00ff9d',
        borderRadius: '16px',
    },
    doneTitle: {
        fontFamily: 'Orbitron, sans-serif',
        color: '#00ff9d',
        fontSize: '1.8rem',
        marginBottom: '1rem',
    },
    doneText: {
        color: 'rgba(255,255,255,0.7)',
        fontSize: '1rem',
        lineHeight: 1.7,
    },
};

export default InstallExtension;
