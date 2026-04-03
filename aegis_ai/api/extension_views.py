"""
aegis.ai — Extension API Views
Lightweight endpoints for the PhishGuard Chrome extension.
These are separate from the dashboard's /api/detect/ to keep concerns clean.
"""
import logging
import uuid

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from core.engine import PhishingEngine
from core.text_analyzer import TextAnalyzer
from core.url_analyzer import URLAnalyzer
from core.rule_engine import RuleEngine
from core.fusion import fuse_scores
from core.sandbox_engine import analyze_remote_file, analyze_filename
from core.ocr_engine import extract_text_from_image_url

logger = logging.getLogger('aegis.ext')

# Shared analyzer instances (loaded once)
_text_analyzer = TextAnalyzer()
_url_analyzer = URLAnalyzer()
_rule_engine = RuleEngine()


def _format_response(score: float, reasons: list, breakdown: dict = None, extra: dict = None):
    """Standard response format for extension endpoints."""
    percentage = round(score * 100)

    if percentage > 50:
        prediction = "Phishing"
        risk_level = "HIGH"
    elif percentage >= 30:
        prediction = "Suspicious"
        risk_level = "MEDIUM"
    else:
        prediction = "Safe"
        risk_level = "LOW"

    result = {
        "prediction": prediction,
        "confidence": percentage,
        "risk_level": risk_level,
        "reasons": reasons[:8],
    }

    if breakdown:
        result["breakdown"] = breakdown
    if extra:
        result.update(extra)

    return result


@method_decorator(csrf_exempt, name='dispatch')
class AnalyzeTextView(APIView):
    """
    POST /api/ext/analyze-text/
    Analyzes email text, messages, or page content for phishing.
    Body: { "text": "..." }
    """
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, FormParser]

    def post(self, request):
        req_id = str(uuid.uuid4())[:8]
        text = request.data.get('text', '').strip()

        if not text:
            return Response(
                {"error": "No text provided"},
                status=status.HTTP_400_BAD_REQUEST
            )

        logger.info(f"[EXT-{req_id}] analyze-text: {len(text)} chars")

        text_result = _text_analyzer.analyze(text)
        rule_result = _rule_engine.analyze({'email_text': text, 'urls': [], 'sender_email': '', 'sender_name': ''})

        final_score = fuse_scores(
            text_result['score'], 0.0, rule_result['score'], has_urls=False
        )

        response = _format_response(
            final_score,
            text_result['reasons'] + rule_result['reasons'],
            breakdown={
                'text_score': text_result['score'],
                'rule_score': rule_result['score'],
            }
        )

        logger.info(f"[EXT-{req_id}] Result: {response['prediction']} ({response['confidence']}%)")
        return Response(response)


@method_decorator(csrf_exempt, name='dispatch')
class AnalyzeURLView(APIView):
    """
    POST /api/ext/analyze-url/
    Analyzes a URL for phishing. Also handles file-link sandbox analysis.
    Body: { "url": "..." }
    """
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, FormParser]

    # File extensions that trigger sandbox analysis
    FILE_EXTENSIONS = {
        '.pdf', '.exe', '.bat', '.cmd', '.scr', '.zip', '.rar', '.7z',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.js', '.vbs', '.ps1', '.msi', '.hta', '.jar', '.apk',
        '.iso', '.img', '.dmg',
    }

    # Image extensions that trigger OCR analysis
    IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.webp', '.bmp', '.gif', '.tiff'}

    def post(self, request):
        req_id = str(uuid.uuid4())[:8]
        url = request.data.get('url', '').strip()

        if not url:
            return Response(
                {"error": "No URL provided"},
                status=status.HTTP_400_BAD_REQUEST
            )

        logger.info(f"[EXT-{req_id}] analyze-url: {url[:100]}")

        # Determine the type of analysis needed
        url_lower = url.lower().split('?')[0]  # Strip query params for extension check
        ext = ''
        for e in self.FILE_EXTENSIONS | self.IMAGE_EXTENSIONS:
            if url_lower.endswith(e):
                ext = e
                break

        # ── Case 1: Image URL → OCR + Text Analysis ──
        if ext in self.IMAGE_EXTENSIONS:
            logger.info(f"[EXT-{req_id}] Image detected ({ext}), running OCR analysis")
            ocr_text = extract_text_from_image_url(url)

            if ocr_text:
                text_result = _text_analyzer.analyze(ocr_text)
                url_result = _url_analyzer.analyze([url])
                final_score = fuse_scores(text_result['score'], url_result['score'], 0.0)
                reasons = text_result['reasons'] + url_result['reasons']
                if ocr_text:
                    reasons.insert(0, f"OCR extracted {len(ocr_text)} chars from image")
            else:
                url_result = _url_analyzer.analyze([url])
                final_score = url_result['score']
                reasons = url_result['reasons']

            response = _format_response(final_score, reasons, extra={
                'scan_type': 'image_ocr',
                'ocr_text_preview': ocr_text[:200] if ocr_text else '',
            })

        # ── Case 2: File URL → Sandbox Analysis ──
        elif ext in self.FILE_EXTENSIONS:
            logger.info(f"[EXT-{req_id}] File link detected ({ext}), running sandbox analysis")
            sandbox_result = analyze_remote_file(url)
            url_result = _url_analyzer.analyze([url])

            combined_score = max(sandbox_result['score'], url_result['score'])
            reasons = sandbox_result['reasons'] + url_result['reasons']

            response = _format_response(combined_score, reasons, extra={
                'scan_type': 'sandbox',
                'sandbox_analysis': sandbox_result.get('analysis', {}),
            })

        # ── Case 3: Normal URL → URL Analysis ──
        else:
            logger.info(f"[EXT-{req_id}] Standard URL analysis")
            url_result = _url_analyzer.analyze([url])

            response = _format_response(
                url_result['score'],
                url_result['reasons'],
                breakdown={'url_score': url_result['score']}
            )
            response['scan_type'] = 'url'

        logger.info(f"[EXT-{req_id}] Result: {response['prediction']} ({response['confidence']}%)")
        return Response(response)


@method_decorator(csrf_exempt, name='dispatch')
class AnalyzeImageView(APIView):
    """
    POST /api/ext/analyze-image/
    Accepts an image URL for OCR-based phishing detection.
    Body: { "image_url": "..." }
    """
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, FormParser]

    def post(self, request):
        req_id = str(uuid.uuid4())[:8]
        image_url = request.data.get('image_url', '').strip()

        if not image_url:
            return Response(
                {"error": "No image_url provided"},
                status=status.HTTP_400_BAD_REQUEST
            )

        logger.info(f"[EXT-{req_id}] analyze-image: {image_url[:100]}")

        # Extract text via OCR
        ocr_text = extract_text_from_image_url(image_url)

        if not ocr_text:
            return Response(_format_response(0.0, ["No text found in image"], extra={
                'scan_type': 'image_ocr',
                'ocr_text_preview': '',
            }))

        # Analyze extracted text
        text_result = _text_analyzer.analyze(ocr_text)
        rule_result = _rule_engine.analyze({
            'email_text': ocr_text, 'urls': [], 'sender_email': '', 'sender_name': ''
        })

        final_score = fuse_scores(text_result['score'], 0.0, rule_result['score'], has_urls=False)

        response = _format_response(
            final_score,
            text_result['reasons'] + rule_result['reasons'],
            extra={
                'scan_type': 'image_ocr',
                'ocr_text_preview': ocr_text[:300],
            }
        )

        logger.info(f"[EXT-{req_id}] Result: {response['prediction']} ({response['confidence']}%)")
        return Response(response)
