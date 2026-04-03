"""
aegis.ai — OCR Engine
Extracts text from images using EasyOCR for phishing detection.
Supports: PNG, JPG, JPEG, WEBP, BMP, TIFF
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
            _reader = False  # Mark as failed, don't retry
        except Exception as e:
            logger.error(f"[ocr_engine.py] EasyOCR init failed: {e}")
            _reader = False
    return _reader if _reader is not False else None


def extract_text_from_image_bytes(image_bytes: bytes) -> str:
    """Extract text from raw image bytes using EasyOCR."""
    reader = _get_reader()
    if reader is None:
        logger.warning("[ocr_engine.py] OCR unavailable — returning empty text")
        return ""

    try:
        # Write to temp file (EasyOCR can read file paths or numpy arrays)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
            tmp.write(image_bytes)
            tmp_path = tmp.name

        results = reader.readtext(tmp_path, detail=0)
        text = ' '.join(results).strip()
        logger.info(f"[ocr_engine.py] Extracted {len(text)} chars from image ({len(image_bytes)} bytes)")

        # Cleanup
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

        resp = requests.get(image_url, timeout=10, stream=True, headers={
            'User-Agent': 'Mozilla/5.0 (Aegis.ai PhishGuard Scanner)'
        })
        resp.raise_for_status()

        # Safety: limit to 10MB
        content = resp.content
        if len(content) > 10 * 1024 * 1024:
            logger.warning("[ocr_engine.py] Image too large (>10MB), skipping OCR")
            return ""

        return extract_text_from_image_bytes(content)

    except Exception as e:
        logger.error(f"[ocr_engine.py] Failed to fetch image: {e}")
        return ""
