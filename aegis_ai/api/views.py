from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import os
import tempfile
import uuid

from core.engine import PhishingEngine
from .serializers import PhishingDetectionSerializer
from core.preprocessor import extract_pdf_text, extract_urls_from_text


@method_decorator(csrf_exempt, name='dispatch')
class PhishingDetectView(APIView):
    """
    aegis.ai - Zero-Day Phishing Detection API
    Handles text, URLs, and PDF attachments with proper cleanup.
    """
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        serializer = PhishingDetectionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "error": "Invalid input",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data

        # Temporary storage for uploaded files
        temp_files = []
        extracted_text_from_pdfs = ""
        all_urls = data.get('urls', [])

        try:
            # Process attachments (PDF support)
            for uploaded_file in data.get('attachments', []):
                # Create secure temp file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
                    tmp.write(uploaded_file.read())
                    temp_path = tmp.name
                    temp_files.append(temp_path)

                # Extract text from PDF
                try:
                    pdf_text = extract_pdf_text(temp_path)
                    extracted_text_from_pdfs += "\n" + pdf_text

                    # Also extract URLs hidden in PDF
                    extracted_urls = extract_urls_from_text(pdf_text)
                    all_urls.extend(extracted_urls)
                except Exception as e:
                    extracted_text_from_pdfs += f"\n[PDF read error: {str(e)}]"

            # Combine all text
            full_text = (data.get('email_text', '') + "\n" + extracted_text_from_pdfs).strip()

            # Prepare clean input for core engine
            input_data = {
                'email_text': full_text,
                'urls': list(set(all_urls)),   # remove duplicates
                'sender_email': data.get('sender_email', ''),
                'sender_name': data.get('sender_name', ''),
            }

            # Run the detection engine
            engine = PhishingEngine()
            result = engine.detect(input_data)

            return Response(result, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": "Internal server error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            for temp_path in temp_files:
                try:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                except Exception:
                    pass   # best effort cleanup