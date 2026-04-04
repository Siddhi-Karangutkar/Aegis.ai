import logging
import uuid
import os
import tempfile
import requests

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
from core.docker_sandbox import run_sandbox

logger = logging.getLogger('aegis.api')

def trigger_isolation(request_id, score, verdict):
    """Notify the local agent to isolate network for critical threats"""
    agent_url = "http://127.0.0.1:5001/isolate"
    try:
        logger.info(f"[REQ-{request_id}] Triggering Network Isolation (Score: {score})")
        response = requests.post(agent_url, json={
            "request_id": request_id,
            "score": score,
            "verdict": verdict
        }, timeout=2)
        if response.status_code == 200:
            logger.info(f"[REQ-{request_id}] Isolation successfully triggered via Agent.")
        else:
            logger.warning(f"[REQ-{request_id}] Agent returned error: {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"[REQ-{request_id}] Could not connect to local agent: {e}")

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
        sandbox_results = []  # Docker sandbox results for each attachment

        try:
            # Process attachments (PDF support + Docker sandbox)
            for i, uploaded_file in enumerate(attachments):
                logger.info(f"[REQ-{request_id}] Processing attachment {i+1}: {uploaded_file.name} ({uploaded_file.size} bytes)")

                # Determine file suffix from original filename
                orig_name = uploaded_file.name or 'unknown'
                suffix = '.' + orig_name.rsplit('.', 1)[-1] if '.' in orig_name else ''

                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(uploaded_file.read())
                    temp_path = tmp.name
                    temp_files.append(temp_path)

                # ── Docker Sandbox Analysis ──
                try:
                    logger.info(f"[REQ-{request_id}]   Running Docker sandbox on: {orig_name}")
                    sb_result = run_sandbox(temp_path, orig_name)
                    sandbox_results.append(sb_result)
                    logger.info(
                        f"[REQ-{request_id}]   Sandbox result: score={sb_result.get('score', 0)}, "
                        f"reasons={sb_result.get('reasons', [])}"
                    )
                except Exception as e:
                    logger.error(f"[REQ-{request_id}]   Docker sandbox error: {e}")
                    sandbox_results.append({'score': 0.0, 'reasons': [f'Sandbox error: {str(e)}']})

                # ── PDF Text Extraction (existing logic) ──
                if suffix.lower() == '.pdf':
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

            # ── Merge Docker sandbox results into final verdict ──
            if sandbox_results:
                max_sandbox_score = max(r.get('score', 0) for r in sandbox_results)
                all_sandbox_reasons = []
                for r in sandbox_results:
                    all_sandbox_reasons.extend(r.get('reasons', []))

                # If sandbox found something worse than the engine, escalate
                if max_sandbox_score > result.get('confidence_score', 0):
                    result['confidence_score'] = round(max(result.get('confidence_score', 0), max_sandbox_score), 2)
                    if max_sandbox_score > 0.5:
                        result['verdict'] = 'PHISHING'
                    elif max_sandbox_score > 0.3:
                        result['verdict'] = 'SUSPICIOUS'

                result['reasons'] = list(dict.fromkeys(
                    result.get('reasons', []) + all_sandbox_reasons
                ))[:10]
                result['sandbox_analysis'] = [
                    r.get('analysis', {}) for r in sandbox_results
                ]
                logger.info(f"[REQ-{request_id}] Sandbox scores merged: max={max_sandbox_score}")

            logger.info(f"[REQ-{request_id}] ── Detection Complete ──")
            logger.info(f"[REQ-{request_id}] Verdict: {result['verdict']} | Score: {result['confidence_score']}")
            logger.info(f"[REQ-{request_id}] Reasons: {result['reasons']}")

            # Trigger Network Isolation for Critical Threats
            # risk_score >= 0.9 or risk_level == "CRITICAL" (malicious in our engine)
            if result['confidence_score'] >= 0.9 or result['verdict'] == 'malicious':
                trigger_isolation(request_id, result['confidence_score'], result['verdict'])
                result['isolation_triggered'] = True
            else:
                result['isolation_triggered'] = False

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