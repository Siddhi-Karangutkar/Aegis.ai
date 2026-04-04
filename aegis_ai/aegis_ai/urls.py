"""
URL configuration for aegis_ai project.
"""

from django.contrib import admin
from django.urls import path, include, re_path
from django.http import HttpResponse
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import render
import zipfile
import io
import os


# Serve the React build's index.html (with asset paths fixed for Django)
def react_app_view(request):
    index_path = os.path.join(settings.BASE_DIR, 'static', 'frontend', 'index.html')
    with open(index_path, 'r') as f:
        content = f.read()
        content = content.replace('"/assets/', '"/static/frontend/assets/')
        content = content.replace('"/favicon.svg', '"/static/frontend/favicon.svg')
        content = content.replace('"/icons.svg', '"/static/frontend/icons.svg')
    return HttpResponse(content)


# Remote testing view preserved
def test_api_view(request):
    return render(request, 'test_api.html')


# Download extension as zip with pre-configured API URL
def download_extension_view(request):
    ext_dir = os.path.join(settings.BASE_DIR, '..', 'extension')
    ext_dir = os.path.abspath(ext_dir)

    if not os.path.isdir(ext_dir):
        return HttpResponse('Extension directory not found', status=404)

    # Detect the public URL (handles ngrok X-Forwarded-Proto)
    host = request.get_host()
    scheme = 'https' if request.is_secure() else 'http'
    if request.META.get('HTTP_X_FORWARDED_PROTO') == 'https':
        scheme = 'https'
    api_url = f"{scheme}://{host}"

    # Build zip in memory
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(ext_dir):
            dirs[:] = [d for d in dirs if d not in ('node_modules', '.git', '__pycache__')]
            for file in files:
                if file.startswith('.') or file == 'test_download.html':
                    continue
                filepath = os.path.join(root, file)
                arcname = os.path.join('PhishGuard', os.path.relpath(filepath, ext_dir))

                # Inject the API URL into background.js
                if file == 'background.js':
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    content = content.replace(
                        "const DEFAULT_API_URL = 'http://localhost:8000';",
                        f"const DEFAULT_API_URL = '{api_url}';"
                    )
                    zf.writestr(arcname, content)
                else:
                    zf.write(filepath, arcname)

    buffer.seek(0)
    response = HttpResponse(buffer.read(), content_type='application/zip')
    response['Content-Disposition'] = 'attachment; filename="PhishGuard-Extension.zip"'
    return response


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
    path('test-api/', test_api_view, name='test_api'),
    path('download-extension/', download_extension_view, name='download_extension'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Catch-all: serve React app for any unmatched route (must be LAST)
urlpatterns += [
    re_path(r'^(?!static/).*$', react_app_view, name='react_app'),
]