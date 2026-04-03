import re
import logging
from pdfminer.high_level import extract_text

logger = logging.getLogger('aegis.preprocessor')


def extract_pdf_text(pdf_path: str) -> str:
    """Extract visible text from PDF"""
    logger.info(f"[preprocessor.py] Extracting text from PDF: {pdf_path}")
    try:
        text = extract_text(pdf_path)
        logger.info(f"[preprocessor.py] PDF extraction success: {len(text)} chars")
        return text.strip()
    except Exception as e:
        logger.error(f"[preprocessor.py] PDF extraction failed: {e}")
        return f"[PDF extraction failed: {str(e)}]"


def extract_urls_from_text(text: str) -> list:
    """Simple regex to extract URLs from text (useful for PDFs)"""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, text)
    unique_urls = list(set(urls))
    logger.info(f"[preprocessor.py] Extracted {len(unique_urls)} URL(s) from text ({len(text)} chars)")
    return unique_urls