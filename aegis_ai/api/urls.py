from django.urls import path
from .views import PhishingDetectView

urlpatterns = [
    path('detect/', PhishingDetectView.as_view(), name='phishing-detect'),
]