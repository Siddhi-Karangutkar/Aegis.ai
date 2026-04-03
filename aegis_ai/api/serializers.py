from rest_framework import serializers

class PhishingDetectionSerializer(serializers.Serializer):
    """
    API Contract for aegis.ai Phishing Detection
    """
    email_text = serializers.CharField(
        required=False, 
        allow_blank=True,
        help_text="The body text of the email"
    )
    
    urls = serializers.ListField(
        child=serializers.URLField(allow_blank=True),
        required=False,
        default=list,
        help_text="List of URLs extracted from the email"
    )
    
    sender_email = serializers.EmailField(
        required=False, 
        allow_blank=True,
        help_text="Email address of the sender (e.g. alert@bank-security.com)"
    )
    
    sender_name = serializers.CharField(
        required=False, 
        allow_blank=True,
        help_text="Display name of the sender (e.g. Bank of America Support)"
    )
    
    # For PDF attachments (basic support)
    attachments = serializers.ListField(
        child=serializers.FileField(),
        required=False,
        default=list,
        help_text="List of uploaded files (PDFs supported)"
    )

    def validate(self, data):
        # At least one of email_text or attachments or urls should be present
        if (not data.get('email_text') and 
            not data.get('attachments') and 
            not data.get('urls')):
            raise serializers.ValidationError(
                "At least one of email_text, urls, or attachments must be provided."
            )
        return data