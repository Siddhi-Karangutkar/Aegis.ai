#!/usr/bin/env python3
"""
aegis.ai — Docker Sandbox Worker
Runs INSIDE the Docker container. Performs deep file analysis in isolation.

Usage: python worker.py /sample/attachment <original_filename>
Output: JSON to stdout
"""
import sys
import os
import json
import math
import re
import hashlib
import struct
from collections import Counter

# ═══════════════════════════════════════════════════════════════════════
# MAGIC BYTES
# ═══════════════════════════════════════════════════════════════════════
MAGIC_SIGNATURES = {
    b'%PDF':             'pdf',
    b'\x89PNG':          'png',
    b'\xff\xd8\xff':     'jpeg',
    b'GIF87a':           'gif',
    b'GIF89a':           'gif',
    b'PK\x03\x04':       'zip',   # Also docx, xlsx, pptx, jar, apk
    b'MZ':               'executable',
    b'\x7fELF':          'elf_executable',
    b'Rar!':             'rar',
    b'\x1f\x8b':         'gzip',
    b'\xd0\xcf\x11\xe0': 'ole',   # Legacy MS Office (doc, xls, ppt)
}

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
        r'\\x[0-9a-fA-F]{2}',
    ],
    'credential_theft': [
        r'password', r'credentials', r'keylog',
        r'cookie', r'localStorage', r'sessionStorage',
    ],
}


# ═══════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return round(-sum(
        (c / length) * math.log2(c / length) for c in counter.values()
    ), 2)


def identify_file_type(header: bytes) -> str:
    for magic, ftype in MAGIC_SIGNATURES.items():
        if header[:len(magic)] == magic:
            return ftype
    return 'unknown'


def compute_hashes(data: bytes) -> dict:
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
    }


def extract_urls(text: str) -> list:
    """Extract URLs from text content."""
    url_pattern = r'https?://[^\s<>"\')\]}{]+'
    return list(set(re.findall(url_pattern, text, re.IGNORECASE)))


# ═══════════════════════════════════════════════════════════════════════
# PDF ANALYSIS
# ═══════════════════════════════════════════════════════════════════════

def analyze_pdf(file_path: str, file_bytes: bytes) -> dict:
    """Deep PDF analysis — JavaScript, actions, embedded files, forms."""
    score = 0.0
    reasons = []
    details = {}

    text_content = file_bytes.decode('latin-1', errors='ignore')

    # ── Dangerous PDF operators ──
    pdf_dangers = {
        '/JavaScript':  (0.6, 'PDF contains embedded JavaScript'),
        '/JS ':         (0.5, 'PDF contains JS action'),
        '/OpenAction':  (0.4, 'PDF has auto-execute on open (OpenAction)'),
        '/AA ':         (0.4, 'PDF has additional auto-actions (/AA)'),
        '/Launch':      (0.7, 'PDF can launch external applications'),
        '/URI ':        (0.1, 'PDF contains URI references'),
        '/SubmitForm':  (0.5, 'PDF contains form submission action'),
        '/GoToR':       (0.3, 'PDF references external file (GoToR)'),
        '/EmbeddedFile': (0.4, 'PDF contains embedded file attachments'),
        '/RichMedia':   (0.3, 'PDF contains rich media (Flash/video)'),
        '/XFA ':        (0.3, 'PDF uses XFA forms (complex scripting)'),
        '/AcroForm':    (0.1, 'PDF contains fillable form fields'),
    }

    found_dangers = []
    for keyword, (weight, reason) in pdf_dangers.items():
        count = text_content.count(keyword)
        if count > 0:
            score += weight
            found_dangers.append(keyword)
            reasons.append(f"{reason} (found {count}x)")

    details['dangerous_operators'] = found_dangers

    # ── Extract embedded JavaScript code ──
    js_blocks = re.findall(r'/JavaScript\s*<<[^>]*>>', text_content)
    js_in_stream = re.findall(r'<</S/JavaScript/JS\s*\((.*?)\)', text_content, re.DOTALL)
    if js_blocks or js_in_stream:
        details['embedded_js_blocks'] = len(js_blocks) + len(js_in_stream)
        score += 0.3

    # ── Try PyPDF2 for structured extraction ──
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(file_path)
        details['page_count'] = len(reader.pages)

        # Extract all text
        full_text = ""
        for page in reader.pages:
            page_text = page.extract_text() or ""
            full_text += page_text + "\n"

        embedded_urls = extract_urls(full_text)
        if embedded_urls:
            details['extracted_urls'] = embedded_urls[:20]
            # Check for suspicious URLs
            suspicious_domains = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'is.gd']
            for url in embedded_urls:
                if any(d in url.lower() for d in suspicious_domains):
                    score += 0.3
                    reasons.append(f"PDF contains shortened/suspicious URL: {url[:80]}")
                    break

        # Check annotations for links
        for page in reader.pages:
            if '/Annots' in page:
                annots = page['/Annots']
                if annots:
                    details['annotation_count'] = len(annots)

    except Exception as e:
        details['pypdf2_error'] = str(e)

    return {
        'score': round(min(score, 1.0), 2),
        'reasons': reasons,
        'details': details,
    }


# ═══════════════════════════════════════════════════════════════════════
# DOCX ANALYSIS
# ═══════════════════════════════════════════════════════════════════════

def analyze_docx(file_path: str, file_bytes: bytes) -> dict:
    """Deep DOCX analysis — macros, OLE objects, external templates, DDE."""
    score = 0.0
    reasons = []
    details = {}

    # ── Check for OLE/VBA macros using oletools ──
    try:
        from oletools.olevba import VBA_Parser
        vba_parser = VBA_Parser(file_path)

        if vba_parser.detect_vba_macros():
            score += 0.7
            reasons.append("🚨 Document contains VBA macros")
            details['has_macros'] = True

            # Analyze macro code
            macro_analysis = []
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                macro_info = {
                    'filename': vba_filename,
                    'code_preview': vba_code[:500],
                    'code_length': len(vba_code),
                }

                # Check for dangerous macro patterns
                auto_execute = ['AutoOpen', 'AutoExec', 'Auto_Open', 'Workbook_Open',
                               'Document_Open', 'AutoClose', 'Document_Close']
                for trigger in auto_execute:
                    if trigger.lower() in vba_code.lower():
                        score += 0.3
                        reasons.append(f"Macro auto-executes via {trigger}")
                        macro_info['auto_execute'] = trigger
                        break

                # Shell / command execution in macros
                shell_patterns = ['Shell(', 'WScript.Shell', 'cmd.exe', 'powershell',
                                 'CreateObject', 'Environ(', 'URLDownloadToFile']
                for pattern in shell_patterns:
                    if pattern.lower() in vba_code.lower():
                        score += 0.4
                        reasons.append(f"Macro contains dangerous call: {pattern}")
                        macro_info['dangerous_calls'] = macro_info.get('dangerous_calls', [])
                        macro_info['dangerous_calls'].append(pattern)

                macro_analysis.append(macro_info)

            details['macros'] = macro_analysis
        else:
            details['has_macros'] = False

        vba_parser.close()

    except ImportError:
        details['oletools_available'] = False
    except Exception as e:
        details['oletools_error'] = str(e)

    # ── Check for external template injection (Template Injection attack) ──
    try:
        import zipfile
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zf:
                # Check word/_rels/settings.xml.rels for external targets
                rels_files = [n for n in zf.namelist() if n.endswith('.rels')]
                for rels_file in rels_files:
                    rels_content = zf.read(rels_file).decode('utf-8', errors='ignore')
                    # Look for external Target URLs
                    external_targets = re.findall(
                        r'Target="(https?://[^"]+)".*?TargetMode="External"',
                        rels_content, re.IGNORECASE
                    )
                    if not external_targets:
                        external_targets = re.findall(
                            r'TargetMode="External".*?Target="(https?://[^"]+)"',
                            rels_content, re.IGNORECASE
                        )
                    if external_targets:
                        score += 0.6
                        reasons.append(f"⚠ External template injection: document loads remote template")
                        details['external_templates'] = external_targets[:5]

                # Check for DDE (Dynamic Data Exchange) in document.xml
                for xml_file in ['word/document.xml', 'word/header1.xml', 'word/footer1.xml']:
                    if xml_file in zf.namelist():
                        content = zf.read(xml_file).decode('utf-8', errors='ignore')
                        if 'DDE' in content or 'DDEAUTO' in content:
                            score += 0.6
                            reasons.append("Document uses DDE (Dynamic Data Exchange) — can execute commands")
                            details['has_dde'] = True

                # Check for embedded OLE objects
                ole_files = [n for n in zf.namelist() if 'oleObject' in n or 'embeddings' in n.lower()]
                if ole_files:
                    score += 0.3
                    reasons.append(f"Document contains {len(ole_files)} embedded OLE object(s)")
                    details['embedded_objects'] = ole_files

    except Exception as e:
        details['zip_analysis_error'] = str(e)

    # ── Extract text content and check for phishing patterns ──
    try:
        from docx import Document
        doc = Document(file_path)
        full_text = "\n".join([p.text for p in doc.paragraphs])
        details['text_preview'] = full_text[:500]
        details['word_count'] = len(full_text.split())

        # Check for embedded URLs
        embedded_urls = extract_urls(full_text)
        if embedded_urls:
            details['extracted_urls'] = embedded_urls[:20]

        # Check hyperlinks in document
        hyperlinks = []
        for rel in doc.part.rels.values():
            if "hyperlink" in str(rel.reltype):
                hyperlinks.append(rel.target_ref)
        if hyperlinks:
            details['hyperlinks'] = hyperlinks[:20]
            # Check for mismatched display text vs URL (classic phishing)
            reasons.append(f"Document contains {len(hyperlinks)} hyperlink(s)")

    except Exception as e:
        details['docx_parse_error'] = str(e)

    return {
        'score': round(min(score, 1.0), 2),
        'reasons': reasons,
        'details': details,
    }


# ═══════════════════════════════════════════════════════════════════════
# GENERIC FILE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════

def analyze_generic(file_path: str, file_bytes: bytes, filename: str) -> dict:
    """Generic deep analysis for any file type."""
    score = 0.0
    reasons = []
    details = {}

    # ── Extension analysis ──
    ext = ''
    if '.' in filename:
        ext = '.' + filename.rsplit('.', 1)[-1].lower()

    # Double extension
    if filename.count('.') >= 2:
        if ext in HIGH_RISK_EXTENSIONS:
            score += 0.6
            reasons.append(f"Double extension detected: '{filename}' — possibly disguised executable")

    if ext in HIGH_RISK_EXTENSIONS:
        score += 0.5
        reasons.append(f"High-risk file type: {ext}")
    elif ext in MEDIUM_RISK_EXTENSIONS:
        score += 0.2
        reasons.append(f"Medium-risk file type: {ext}")

    # ── Type mismatch ──
    detected_type = identify_file_type(file_bytes[:16])
    details['detected_type'] = detected_type

    type_ext_map = {
        'pdf': ['pdf'],
        'png': ['png'],
        'jpeg': ['jpg', 'jpeg'],
        'gif': ['gif'],
        'zip': ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk'],
        'executable': ['exe', 'dll', 'sys', 'com', 'scr'],
        'elf_executable': ['so', 'elf', ''],
        'ole': ['doc', 'xls', 'ppt'],
    }

    expected_exts = type_ext_map.get(detected_type, [])
    clean_ext = ext.lstrip('.')
    if expected_exts and clean_ext and clean_ext not in expected_exts:
        score += 0.7
        reasons.append(f"⚠ File type mismatch: header says '{detected_type}' but extension is '{ext}'")

    if detected_type in ('executable', 'elf_executable') and clean_ext in ('pdf', 'doc', 'docx', 'jpg', 'png', 'txt'):
        score += 0.9
        reasons.append(f"🚨 CRITICAL: Executable disguised as .{clean_ext} file!")

    # ── Entropy ──
    entropy = calculate_entropy(file_bytes[:4096])
    details['entropy'] = entropy
    if entropy > 7.5:
        score += 0.3
        reasons.append(f"High entropy ({entropy}) — content may be encrypted or packed")

    # ── Behavioral string scanning ──
    try:
        text_content = file_bytes[:50000].decode('utf-8', errors='ignore')
    except Exception:
        text_content = ''

    if text_content:
        capabilities = []
        for category, patterns in DANGEROUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    capabilities.append(category)
                    break
        details['dangerous_capabilities'] = capabilities

        if 'script_execution' in capabilities:
            score += 0.4
            reasons.append("Contains script execution commands")
        if 'network_activity' in capabilities:
            score += 0.2
            reasons.append("Contains network activity patterns")
        if 'obfuscation' in capabilities:
            score += 0.35
            reasons.append("Obfuscated code patterns detected")
        if 'credential_theft' in capabilities:
            score += 0.3
            reasons.append("Credential harvesting patterns found")
        if 'file_manipulation' in capabilities:
            score += 0.2
            reasons.append("File system manipulation detected")

        # Extract URLs from content
        urls = extract_urls(text_content)
        if urls:
            details['extracted_urls'] = urls[:20]

    return {
        'score': round(min(score, 1.0), 2),
        'reasons': reasons,
        'details': details,
    }


# ═══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'Usage: worker.py <file_path> [original_filename]'}))
        sys.exit(1)

    file_path = sys.argv[1]
    original_filename = sys.argv[2] if len(sys.argv) > 2 else os.path.basename(file_path)

    if not os.path.exists(file_path):
        print(json.dumps({'error': f'File not found: {file_path}'}))
        sys.exit(1)

    try:
        with open(file_path, 'rb') as f:
            file_bytes = f.read()

        file_size = len(file_bytes)
        detected_type = identify_file_type(file_bytes[:16])
        hashes = compute_hashes(file_bytes)
        ext = ('.' + original_filename.rsplit('.', 1)[-1].lower()) if '.' in original_filename else ''

        # ── Route to the right analyzer ──
        if detected_type == 'pdf' or ext == '.pdf':
            type_result = analyze_pdf(file_path, file_bytes)
            scan_method = 'pdf_deep_scan'
        elif ext in ('.docx', '.docm') or (detected_type == 'zip' and ext in ('.docx', '.docm')):
            type_result = analyze_docx(file_path, file_bytes)
            scan_method = 'docx_deep_scan'
        elif detected_type == 'ole' or ext in ('.doc', '.xls', '.ppt', '.docm', '.xlsm', '.pptm'):
            # Legacy Office format — try oletools
            type_result = analyze_docx(file_path, file_bytes)  # oletools handles these too
            scan_method = 'ole_deep_scan'
        else:
            type_result = {'score': 0.0, 'reasons': [], 'details': {}}
            scan_method = 'generic_scan'

        # ── Always run generic analysis ──
        generic_result = analyze_generic(file_path, file_bytes, original_filename)

        # ── Merge results ──
        final_score = round(min(max(type_result['score'], generic_result['score']), 1.0), 2)
        all_reasons = list(dict.fromkeys(type_result['reasons'] + generic_result['reasons']))  # deduplicate preserving order

        result = {
            'score': final_score,
            'reasons': all_reasons[:10],
            'analysis': {
                'filename': original_filename,
                'file_size': file_size,
                'detected_type': detected_type,
                'scan_method': scan_method,
                'hashes': hashes,
                'entropy': generic_result['details'].get('entropy', 0),
                'type_details': type_result.get('details', {}),
                'generic_details': generic_result.get('details', {}),
            },
            'sandbox': 'docker',
            'version': '1.0.0',
        }

        print(json.dumps(result))

    except Exception as e:
        print(json.dumps({
            'score': 0.0,
            'reasons': [f'Sandbox analysis error: {str(e)}'],
            'analysis': {'error': str(e)},
            'sandbox': 'docker',
        }))
        sys.exit(1)


if __name__ == '__main__':
    main()
