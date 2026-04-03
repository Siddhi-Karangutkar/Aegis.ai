from rest_framework import serializers


class PhishingDetectionSerializer(serializers.Serializer):
    """
    API Contract for aegis.ai Phishing Detection
    Accepts text, URLs (as string or list), sender info, and file attachments.
    """
    email_text = serializers.CharField(
        required=False, 
        allow_blank=True,
        default='',
        help_text="The body text of the email"
    )
    
    # Accept URLs as a single string (comma/space separated) or a list
    urls = serializers.CharField(
        required=False,
        allow_blank=True,
        default='',
        help_text="URL(s) to analyze — can be a single URL or comma-separated"
    )
    
    sender_email = serializers.EmailField(
        required=False, 
        allow_blank=True,
        default='',
        help_text="Email address of the sender"
    )
    
    sender_name = serializers.CharField(
        required=False, 
        allow_blank=True,
        default='',
        help_text="Display name of the sender"
    )
    
    # For PDF attachments
    attachments = serializers.ListField(
        child=serializers.FileField(),
        required=False,
        default=list,
        help_text="List of uploaded files (PDFs supported)"
    )

    def validate_urls(self, value):
        """Convert URL string input to a list of URLs."""
        if not value:
            return []
        if isinstance(value, list):
            return value
        # Split by common delimiters (comma, space, newline)
        import re
        urls = re.split(r'[,\s\n]+', value.strip())
        return [u.strip() for u in urls if u.strip()]

    def validate(self, data):
        # At least one of email_text, attachments, or urls should be present
        has_text = bool(data.get('email_text', '').strip())
        has_urls = bool(data.get('urls'))
        has_files = bool(data.get('attachments'))
        
        if not has_text and not has_urls and not has_files:
            raise serializers.ValidationError(
                "At least one of email_text, urls, or attachments must be provided."
            )
        return data