from django.urls import path
from .views import PhishingDetectView
from .extension_views import AnalyzeTextView, AnalyzeURLView, AnalyzeImageView

urlpatterns = [
    # Dashboard API (existing)
    path('detect/', PhishingDetectView.as_view(), name='phishing-detect'),

    # Extension API endpoints
    path('ext/analyze-text/', AnalyzeTextView.as_view(), name='ext-analyze-text'),
    path('ext/analyze-url/', AnalyzeURLView.as_view(), name='ext-analyze-url'),
    path('ext/analyze-image/', AnalyzeImageView.as_view(), name='ext-analyze-image'),
]