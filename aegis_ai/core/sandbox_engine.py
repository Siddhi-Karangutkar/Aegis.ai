"""
aegis.ai — Sandbox Engine
Remote file analysis without user downloading.
Performs: header validation, behavioral string scanning, metadata inspection.
"""
import logging
import struct
import re
import math
from collections import Counter

logger = logging.getLogger('aegis.sandbox')

# ─── Magic Byte Signatures ──────────────────────────────────────────
MAGIC_SIGNATURES = {
    b'%PDF':        'pdf',
    b'\x89PNG':     'png',
    b'\xff\xd8\xff': 'jpeg',
    b'GIF87a':      'gif',
    b'GIF89a':      'gif',
    b'PK\x03\x04':  'zip',  # Also: docx, xlsx, pptx, jar, apk
    b'MZ':          'executable',  # PE/EXE/DLL
    b'\x7fELF':     'elf_executable',
    b'Rar!':        'rar',
    b'\x1f\x8b':    'gzip',
    b'\xd0\xcf\x11\xe0': 'ole',  # Old MS Office (doc, xls, ppt)
}

# ─── Dangerous Behavioral Patterns ──────────────────────────────────
DANGEROUS_PATTERNS = {
    'script_execution': [
        r'eval\s*\(', r'exec\s*\(', r'system\s*\(', r'shell_exec',
        r'subprocess', r'os\.system', r'Runtime\.exec',
        r'WScript\.Shell', r'powershell', r'cmd\.exe',
    ],
    'network_activity': [
        r'XMLHttpRequest', r'fetch\s*\(', r'socket\.',
        r'http\.get', r'urllib', r'requests\.get',
        r'curl\s', r'wget\s',
    ],
    'file_manipulation': [
        r'fs\.unlink', r'fs\.writeFile', r'rmdir',
        r'os\.remove', r'shutil\.rmtree', r'DeleteFile',
    ],
    'obfuscation': [
        r'unescape\s*\(', r'String\.fromCharCode',
        r'atob\s*\(', r'base64\.b64decode',
        r'\\x[0-9a-fA-F]{2}',  # Hex-encoded strings
    ],
    'credential_theft': [
        r'password', r'credentials', r'keylog',
        r'cookie', r'localStorage', r'sessionStorage',
    ],
}

# ─── High-Risk File Extensions ──────────────────────────────────────
HIGH_RISK_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.scr', '.pif',
    '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
    '.ps1', '.psm1', '.msi', '.msp', '.hta', '.cpl',
    '.inf', '.reg', '.lnk', '.dll', '.sys',
}

MEDIUM_RISK_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm',
    '.jar', '.apk', '.iso', '.img', '.dmg',
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data. High entropy = possibly encrypted/compressed."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 2)


def identify_file_type(header_bytes: bytes) -> str:
    """Identify file type from magic bytes."""
    for magic, file_type in MAGIC_SIGNATURES.items():
        if header_bytes[:len(magic)] == magic:
            return file_type
    return 'unknown'


def analyze_filename(filename: str) -> dict:
    """Static analysis based on filename patterns."""
    score = 0.0
    reasons = []
    filename_lower = filename.lower()

    # Extract extension
    parts = filename.rsplit('.', 1)
    ext = f'.{parts[-1]}' if len(parts) > 1 else ''

    # Double extension detection (e.g., invoice.pdf.exe)
    dot_count = filename.count('.')
    if dot_count >= 2:
        inner_ext = f'.{filename.rsplit(".", 2)[-2]}' if dot_count >= 2 else ''
        if ext in HIGH_RISK_EXTENSIONS:
            score += 0.6
            reasons.append(f"Double extension detected: '{filename}' — likely disguised executable")

    # High-risk extension
    if ext in HIGH_RISK_EXTENSIONS:
        score += 0.5
        reasons.append(f"High-risk file type: {ext}")
    elif ext in MEDIUM_RISK_EXTENSIONS:
        score += 0.2
        reasons.append(f"Medium-risk file type: {ext}")

    # Suspicious naming patterns
    suspicious_names = ['invoice', 'payment', 'urgent', 'verify', 'account',
                       'security', 'update', 'confirm', 'reset', 'bank']
    matches = [n for n in suspicious_names if n in filename_lower]
    if matches and (ext in HIGH_RISK_EXTENSIONS or ext in MEDIUM_RISK_EXTENSIONS):
        score += 0.3
        reasons.append(f"Social engineering filename: contains {', '.join(matches)}")

    # Unicode trickery (right-to-left override, zero-width chars)
    if any(ord(c) > 8000 for c in filename):
        score += 0.5
        reasons.append("Unicode manipulation detected in filename")

    return {
        'score': round(min(score, 1.0), 2),
        'reasons': reasons,
        'extension': ext,
    }


def analyze_file_content(file_bytes: bytes, filename: str = '') -> dict:
    """
    Deep structural analysis of file content.
    This is the sandbox's core inspection engine.
    """
    score = 0.0
    reasons = []
    analysis = {
        'file_size': len(file_bytes),
        'detected_type': 'unknown',
        'claimed_extension': '',
        'entropy': 0.0,
        'dangerous_capabilities': [],
    }

    if not file_bytes:
        return {'score': 0.0, 'reasons': ['Empty file'], 'analysis': analysis}

    # ── 1. Magic Byte Identification ──
    detected_type = identify_file_type(file_bytes[:16])
    analysis['detected_type'] = detected_type

    # ── 2. Extension Mismatch Detection ──
    if filename:
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        analysis['claimed_extension'] = ext

        type_ext_map = {
            'pdf': ['pdf'],
            'png': ['png'],
            'jpeg': ['jpg', 'jpeg'],
            'gif': ['gif'],
            'zip': ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk'],
            'executable': ['exe', 'dll', 'sys', 'com', 'scr'],
            'elf_executable': ['so', 'elf', ''],
        }

        expected_exts = type_ext_map.get(detected_type, [])
        if expected_exts and ext and ext not in expected_exts:
            score += 0.7
            reasons.append(
                f"⚠ File type mismatch: header says '{detected_type}' but extension is '.{ext}'"
            )

        # Executable disguised as document
        if detected_type in ('executable', 'elf_executable') and ext in ('pdf', 'doc', 'docx', 'jpg', 'png', 'txt'):
            score += 0.9
            reasons.append(f"🚨 CRITICAL: Executable disguised as .{ext} file!")

    # ── 3. Entropy Analysis ──
    # Sample first 4KB for efficiency
    sample = file_bytes[:4096]
    entropy = calculate_entropy(sample)
    analysis['entropy'] = entropy

    if entropy > 7.5:
        score += 0.3
        reasons.append(f"High entropy ({entropy}) — content may be encrypted or packed")

    # ── 4. Behavioral String Scanning ──
    # Try to decode content as text for pattern scanning
    try:
        text_content = file_bytes[:50000].decode('utf-8', errors='ignore')
    except Exception:
        text_content = ''

    if text_content:
        capabilities_found = []
        for category, patterns in DANGEROUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    capabilities_found.append(category)
                    break

        analysis['dangerous_capabilities'] = capabilities_found

        if 'script_execution' in capabilities_found:
            score += 0.4
            reasons.append("Contains script execution commands")
        if 'network_activity' in capabilities_found:
            score += 0.2
            reasons.append("Contains network activity patterns")
        if 'obfuscation' in capabilities_found:
            score += 0.35
            reasons.append("Obfuscated code patterns detected")
        if 'credential_theft' in capabilities_found:
            score += 0.3
            reasons.append("Credential harvesting patterns found")
        if 'file_manipulation' in capabilities_found:
            score += 0.2
            reasons.append("File system manipulation detected")

    # ── 5. PDF-Specific Checks ──
    if detected_type == 'pdf' and text_content:
        pdf_dangers = ['/JavaScript', '/JS ', '/OpenAction', '/AA ',
                       '/Launch', '/URI ', '/SubmitForm', '/GoToR']
        found = [d for d in pdf_dangers if d in text_content]
        if found:
            score += 0.5
            reasons.append(f"PDF contains active content: {', '.join(found)}")

    return {
        'score': round(min(score, 1.0), 2),
        'reasons': reasons[:8],
        'analysis': analysis,
    }


def analyze_remote_file(url: str) -> dict:
    """
    Fetch a file from URL and perform sandbox analysis.
    The user never downloads the file — the server does it safely.
    """
    try:
        import requests

        logger.info(f"[sandbox_engine.py] Fetching remote file: {url[:100]}")

        # Stream download with size limit (15MB max)
        resp = requests.get(url, timeout=15, stream=True, headers={
            'User-Agent': 'Mozilla/5.0 (Aegis.ai Sandbox Scanner)'
        })
        resp.raise_for_status()

        # Read with size limit
        max_size = 15 * 1024 * 1024
        content = b''
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > max_size:
                logger.warning(f"[sandbox_engine.py] File exceeds 15MB limit, truncating")
                break

        # Extract filename from URL or Content-Disposition
        filename = ''
        cd = resp.headers.get('Content-Disposition', '')
        if 'filename=' in cd:
            filename = cd.split('filename=')[-1].strip('"\'')
        if not filename:
            filename = url.split('/')[-1].split('?')[0]

        logger.info(f"[sandbox_engine.py] Downloaded {len(content)} bytes, filename: {filename}")

        # Run structural analysis
        result = analyze_file_content(content, filename)

        # Also run filename analysis
        fname_result = analyze_filename(filename)
        result['score'] = round(min(max(result['score'], fname_result['score']), 1.0), 2)
        result['reasons'] = list(set(result['reasons'] + fname_result['reasons']))[:8]
        result['analysis']['filename'] = filename

        return result

    except requests.exceptions.RequestException as e:
        logger.error(f"[sandbox_engine.py] Failed to fetch: {e}")
        return {
            'score': 0.0,
            'reasons': [f"Could not fetch file: {str(e)}"],
            'analysis': {'error': str(e)},
        }
    except Exception as e:
        logger.error(f"[sandbox_engine.py] Sandbox error: {e}")
        return {
            'score': 0.0,
            'reasons': [f"Analysis error: {str(e)}"],
            'analysis': {'error': str(e)},
        }
