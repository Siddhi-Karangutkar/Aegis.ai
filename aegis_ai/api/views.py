import logging
import uuid
import os
import tempfile

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from core.engine import PhishingEngine
from .serializers import PhishingDetectionSerializer
from core.preprocessor import extract_pdf_text, extract_urls_from_text

logger = logging.getLogger('aegis.api')


@method_decorator(csrf_exempt, name='dispatch')
class PhishingDetectView(APIView):
    """
    aegis.ai - Zero-Day Phishing Detection API
    Handles text, URLs, and PDF attachments with proper cleanup.
    """
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        request_id = str(uuid.uuid4())[:8]
        client_ip = self._get_client_ip(request)

        logger.info("═" * 60)
        logger.info(f"[REQ-{request_id}] ── New Detection Request ──")
        logger.info(f"[REQ-{request_id}] Client IP: {client_ip}")
        logger.info(f"[REQ-{request_id}] Content-Type: {request.content_type}")

        serializer = PhishingDetectionSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning(f"[REQ-{request_id}] Validation failed: {serializer.errors}")
            return Response({
                "error": "Invalid input",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data

        # Log what the user submitted
        email_text = data.get('email_text', '')
        urls = data.get('urls', [])
        sender = data.get('sender_email', '')
        attachments = data.get('attachments', [])

        logger.info(f"[REQ-{request_id}] Input summary:")
        logger.info(f"[REQ-{request_id}]   Email text: {len(email_text)} chars | Preview: {email_text[:80]!r}...")
        logger.info(f"[REQ-{request_id}]   URLs provided: {len(urls)} → {urls[:3]}")
        logger.info(f"[REQ-{request_id}]   Sender: {sender or '(not provided)'}")
        logger.info(f"[REQ-{request_id}]   Attachments: {len(attachments)} file(s)")

        # Temporary storage for uploaded files
        temp_files = []
        extracted_text_from_pdfs = ""
        all_urls = list(urls)

        try:
            # Process attachments (PDF support)
            for i, uploaded_file in enumerate(attachments):
                logger.info(f"[REQ-{request_id}] Processing attachment {i+1}: {uploaded_file.name} ({uploaded_file.size} bytes)")

                with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
                    tmp.write(uploaded_file.read())
                    temp_path = tmp.name
                    temp_files.append(temp_path)

                try:
                    pdf_text = extract_pdf_text(temp_path)
                    extracted_text_from_pdfs += "\n" + pdf_text
                    extracted_urls = extract_urls_from_text(pdf_text)
                    all_urls.extend(extracted_urls)
                    logger.info(f"[REQ-{request_id}]   PDF extracted: {len(pdf_text)} chars, {len(extracted_urls)} URLs found")
                except Exception as e:
                    logger.error(f"[REQ-{request_id}]   PDF extraction error: {e}")
                    extracted_text_from_pdfs += f"\n[PDF read error: {str(e)}]"

            # Combine all text
            full_text = (email_text + "\n" + extracted_text_from_pdfs).strip()

            input_data = {
                'email_text': full_text,
                'urls': list(set(all_urls)),
                'sender_email': data.get('sender_email', ''),
                'sender_name': data.get('sender_name', ''),
            }

            logger.info(f"[REQ-{request_id}] ── Triggering Detection Pipeline ──")
            logger.info(f"[REQ-{request_id}] → core/engine.py → PhishingEngine.detect()")

            # Run the detection engine
            engine = PhishingEngine()
            result = engine.detect(input_data, request_id=request_id)

            logger.info(f"[REQ-{request_id}] ── Detection Complete ──")
            logger.info(f"[REQ-{request_id}] Verdict: {result['verdict']} | Score: {result['confidence_score']}")
            logger.info(f"[REQ-{request_id}] Reasons: {result['reasons']}")
            logger.info("═" * 60)

            return Response(result, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"[REQ-{request_id}] ❌ Internal error: {e}", exc_info=True)
            return Response({
                "error": "Internal server error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            for temp_path in temp_files:
                try:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                        logger.info(f"[REQ-{request_id}] Cleaned up temp file: {temp_path}")
                except Exception:
                    pass

    def _get_client_ip(self, request):
        x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded:
            return x_forwarded.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')