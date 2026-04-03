from pdfminer.high_level import extract_text
import re

def extract_pdf_text(pdf_path: str) -> str:
    """Extract visible text from PDF"""
    try:
        text = extract_text(pdf_path)
        return text.strip()
    except Exception as e:
        return f"[PDF extraction failed: {str(e)}]"


def extract_urls_from_text(text: str) -> list:
    """Simple regex to extract URLs from text (useful for PDFs)"""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))  # remove duplicates