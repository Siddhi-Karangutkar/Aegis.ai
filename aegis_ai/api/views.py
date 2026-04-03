from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.files.storage import default_storage
import os

from core.engine import PhishingEngine
from .serializers import PhishingDetectionSerializer


class PhishingDetectView(APIView):
    """
    aegis.ai - Zero-Day Phishing Detection API
    """
    def post(self, request):
        serializer = PhishingDetectionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data

        # Handle file attachments (PDF support)
        extracted_text_from_pdfs = ""
        file_paths = []

        for file in data.get('attachments', []):
            # Save temporarily
            filename = default_storage.save(f'attachments/{file.name}', file)
            file_path = default_storage.path(filename)
            file_paths.append(file_path)

            # Extract text from PDF
            try:
                from core.preprocessor import extract_pdf_text
                extracted_text_from_pdfs += "\n" + extract_pdf_text(file_path)
            except Exception as e:
                extracted_text_from_pdfs += f"\n[Error reading PDF: {str(e)}]"

        # Combine email_text with extracted PDF text
        full_text = data.get('email_text', '') + "\n" + extracted_text_from_pdfs

        # Prepare input for core engine
        input_data = {
            'email_text': full_text.strip(),
            'urls': data.get('urls', []),
            'sender_email': data.get('sender_email', ''),
            'sender_name': data.get('sender_name', ''),
        }

        # Run the core engine
        engine = PhishingEngine()
        result = engine.detect(input_data)

        # Clean up temporary files
        for path in file_paths:
            try:
                os.remove(path)
            except:
                pass

        return Response(result, status=status.HTTP_200_OK)