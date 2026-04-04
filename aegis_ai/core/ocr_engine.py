"""
aegis.ai — OCR Engine
Extracts text from images using EasyOCR for phishing detection.
Supports: PNG, JPG, JPEG, WEBP, BMP, TIFF, GIF (via PIL normalization)
"""
import logging
import io
import os
import tempfile

logger = logging.getLogger('aegis.ocr')

# Lazy-load EasyOCR (heavy import)
_reader = None


def _get_reader():
    global _reader
    if _reader is None:
        try:
            import easyocr
            _reader = easyocr.Reader(['en'], gpu=False, verbose=False)
            logger.info("[ocr_engine.py] EasyOCR reader initialized (CPU mode)")
        except ImportError:
            logger.error("[ocr_engine.py] EasyOCR not installed. Run: pip install easyocr")
            _reader = False
        except Exception as e:
            logger.error(f"[ocr_engine.py] EasyOCR init failed: {e}")
            _reader = False
    return _reader if _reader is not False else None


def _normalize_image_bytes(image_bytes: bytes):
    """
    Normalize raw image bytes to a clean RGB PNG that EasyOCR can always read.

    Returns (normalized_bytes: bytes) on success, or None if the input is not
    a recognizable image (e.g. HTML error page, redirect body, corrupt data).

    Handles:
    - Palette-mode images (P/PA) with or without transparency
    - RGBA / LA images (alpha composited onto white background)
    - Animated GIFs (first frame only)
    - JPEG, WEBP, BMP, TIFF, and any other PIL-supported format
    """
    try:
        from PIL import Image
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")   # suppress PIL palette/transparency warnings
            bio = io.BytesIO(image_bytes)
            img = Image.open(bio)
            img.verify()                       # raises if file is truncated / not an image

        # Re-open after verify() (verify() leaves the file pointer in an unusable state)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            img = Image.open(io.BytesIO(image_bytes))

            # Animated GIF — take first frame only
            if getattr(img, 'is_animated', False):
                img.seek(0)

            if img.mode != 'RGB':
                if img.mode in ('RGBA', 'LA', 'PA'):
                    # Composite transparent image onto white background
                    if img.mode == 'PA':
                        img = img.convert('RGBA')
                    background = Image.new('RGB', img.size, (255, 255, 255))
                    background.paste(img, mask=img.split()[-1])
                    img = background
                else:
                    img = img.convert('RGB')

            out = io.BytesIO()
            img.save(out, format='PNG')
            return out.getvalue()

    except Exception as e:
        logger.warning(f"[ocr_engine.py] PIL normalization failed ({e}) — bytes are not a valid image, skipping OCR")
        return None    # ← explicit None so callers know to abort, not fall through


def extract_text_from_image_bytes(image_bytes: bytes) -> str:
    """Extract text from raw image bytes using EasyOCR, or PyPDF2 if it's a PDF."""
    
    # ── Fallback for PDFs ──
    if image_bytes.startswith(b'%PDF'):
        try:
            import PyPDF2
            logger.info("[ocr_engine.py] PDF detected via magic bytes. Bypassing OCR and using PyPDF2 fallback.")
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(image_bytes))
            text = " ".join(page.extract_text() for page in pdf_reader.pages if page.extract_text())
            logger.info(f"[ocr_engine.py] Extracted {len(text)} chars from PDF ({len(image_bytes)} bytes)")
            return text.strip()
        except ImportError:
            logger.error("[ocr_engine.py] PyPDF2 not installed. Run: pip install PyPDF2")
            return ""
        except Exception as e:
            logger.error(f"[ocr_engine.py] PyPDF2 fallback failed: {e}")
            return ""

    # Validate + normalize before touching EasyOCR
    normalized_bytes = _normalize_image_bytes(image_bytes)
    if normalized_bytes is None:
        # Not a valid image (e.g. HTML response, corrupt data) — abort cleanly
        logger.warning("[ocr_engine.py] Input is not a valid image or PDF — skipping OCR")
        return ""

    reader = _get_reader()
    if reader is None:
        logger.warning("[ocr_engine.py] OCR unavailable — returning empty text")
        return ""

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
            tmp.write(normalized_bytes)
            tmp_path = tmp.name

        results = reader.readtext(tmp_path, detail=0)
        text = ' '.join(results).strip()
        logger.info(
            f"[ocr_engine.py] Extracted {len(text)} chars "
            f"(raw={len(image_bytes)}B → normalized={len(normalized_bytes)}B)"
        )

        try:
            os.unlink(tmp_path)
        except Exception:
            pass

        return text

    except Exception as e:
        logger.error(f"[ocr_engine.py] OCR extraction failed: {e}")
        return ""


def extract_text_from_image_url(image_url: str) -> str:
    """Fetch an image from URL and extract text via OCR."""
    try:
        import requests
        logger.info(f"[ocr_engine.py] Fetching image from: {image_url[:80]}")

        resp = requests.get(image_url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Aegis.ai PhishGuard Scanner)'
        })
        resp.raise_for_status()

        # Reject non-image Content-Type early (catches HTML error pages, redirects, etc.)
        content_type = resp.headers.get('Content-Type', '').lower()
        if content_type and not any(t in content_type for t in (
            'image/', 'octet-stream', 'application/octet'
        )):
            logger.warning(
                f"[ocr_engine.py] URL did not return an image "
                f"(Content-Type: {content_type}) — skipping OCR"
            )
            return ""

        content = resp.content
        if not content:
            logger.warning("[ocr_engine.py] Empty response body — skipping OCR")
            return ""

        if len(content) > 10 * 1024 * 1024:
            logger.warning("[ocr_engine.py] Image too large (>10MB) — skipping OCR")
            return ""

        return extract_text_from_image_bytes(content)

    except Exception as e:
        logger.error(f"[ocr_engine.py] Failed to fetch image: {e}")
        return ""