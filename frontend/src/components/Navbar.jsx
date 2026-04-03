import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Menu, X } from 'lucide-react';

const Navbar = () => {
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);

    const toggleSidebar = () => {
        setIsSidebarOpen(!isSidebarOpen);
    };

    const sidebarLinks = [
        { path: '/', label: 'Home' },
        { path: '/report', label: 'Threat Detection Dashboard' },
        { path: 'https://threatmap.checkpoint.com/', label: 'Live Threat Map', external: true },
        { path: '/awareness', label: 'Phishing Awareness Hub' },
        { path: '/cases', label: 'Real Case Studies' },
        { path: '/quiz', label: 'Interactive Quiz' },
        { path: '/stats', label: 'Phishing Statistics' },
        { path: '/indicators', label: 'Indicators Guide' },
        { path: '/urlsafety', label: 'URL Safety Guide' },
        { path: '/bestpractices', label: 'Security Best Practices' },
        { path: '/blog', label: 'Threat Intelligence Blog' },
        { path: '/technology', label: 'About the Technology' },
    ];

    return (
        <>
            <nav style={styles.nav}>
                <div style={styles.leftSection}>
                    <button onClick={toggleSidebar} style={styles.menuButton}>
                        <Menu size={28} color="var(--primary-accent)" />
                    </button>
                    <Link to="/" style={styles.logo}>Aegis.ai</Link>
                </div>
                
                <div style={styles.navLinks}>
                    <Link to="/technology" style={styles.link}>Technology</Link>
                    <Link to="/report" style={styles.link}>Report Threat</Link>
                </div>
            </nav>

            {/* Sidebar Overlay */}
            <div style={{
                ...styles.sidebarOverlay,
                opacity: isSidebarOpen ? 1 : 0,
                pointerEvents: isSidebarOpen ? 'auto' : 'none'
            }} onClick={toggleSidebar}></div>

            {/* Sidebar Navigation */}
            <div style={{
                ...styles.sidebar,
                transform: isSidebarOpen ? 'translateX(0)' : 'translateX(-100%)'
            }}>
                <div style={styles.sidebarHeader}>
                    <h2 style={styles.sidebarTitle}>Navigation</h2>
                    <button onClick={toggleSidebar} style={styles.closeButton}>
                        <X size={28} color="var(--text-light)" />
                    </button>
                </div>
                <div style={styles.sidebarLinksContainer}>
                    {sidebarLinks.map((link, idx) => (
                        link.external ? (
                            <a 
                                key={idx} 
                                href={link.path} 
                                target="_blank" 
                                rel="noopener noreferrer"
                                style={styles.sidebarLink}
                                onClick={toggleSidebar}
                            >
                                {link.label}
                            </a>
                        ) : (
                            <Link 
                                key={idx} 
                                to={link.path} 
                                style={styles.sidebarLink}
                                onClick={toggleSidebar}
                            >
                                {link.label}
                            </Link>
                        )
                    ))}
                </div>
            </div>
        </>
    );
};

const styles = {
    nav: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '1.5rem 4rem',
        position: 'fixed',
        top: 0,
        width: '100%',
        zIndex: 100,
        background: 'rgba(10, 14, 23, 0.85)',
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid var(--glass-border)'
    },
    leftSection: {
        display: 'flex',
        alignItems: 'center',
        gap: '2rem'
    },
    menuButton: {
        background: 'none',
        border: 'none',
        cursor: 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
    },
    logo: {
        fontFamily: 'Orbitron, sans-serif',
        fontSize: '1.8rem',
        color: 'var(--primary-accent)',
        fontWeight: 700,
        textShadow: '0 0 15px rgba(0, 210, 255, 0.4)',
        textDecoration: 'none'
    },
    navLinks: {
        display: 'flex',
        gap: '2.5rem'
    },
    link: {
        color: 'var(--text-light)',
        fontWeight: 500,
        fontSize: '0.95rem',
        transition: 'color 0.3s',
        textDecoration: 'none'
    },
    
    // Sidebar Styles
    sidebarOverlay: {
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100vw',
        height: '100vh',
        background: 'rgba(0, 0, 0, 0.6)',
        backdropFilter: 'blur(4px)',
        zIndex: 1000,
        transition: 'opacity 0.3s ease'
    },
    sidebar: {
        position: 'fixed',
        top: 0,
        left: 0,
        width: '350px',
        maxWidth: '80vw',
        height: '100vh',
        background: 'rgba(10, 14, 23, 0.95)',
        borderRight: '1px solid var(--glass-border)',
        zIndex: 1001,
        transition: 'transform 0.4s cubic-bezier(0.77, 0, 0.175, 1)',
        display: 'flex',
        flexDirection: 'column',
        boxShadow: '10px 0 30px rgba(0,0,0,0.5)'
    },
    sidebarHeader: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '2rem',
        borderBottom: '1px solid var(--glass-border)'
    },
    sidebarTitle: {
        color: 'var(--primary-accent)',
        fontFamily: 'Orbitron, sans-serif',
        fontSize: '1.4rem'
    },
    closeButton: {
        background: 'none',
        border: 'none',
        cursor: 'pointer'
    },
    sidebarLinksContainer: {
        display: 'flex',
        flexDirection: 'column',
        padding: '2rem',
        gap: '1.5rem',
        overflowY: 'auto'
    },
    sidebarLink: {
        color: 'var(--text-light)',
        fontSize: '1.1rem',
        textDecoration: 'none',
        transition: 'color 0.2s ease',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
        paddingBottom: '0.5rem'
    }
};

export default Navbar;
