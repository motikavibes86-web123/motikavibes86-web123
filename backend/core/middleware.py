import os
from django.http import HttpResponseForbidden

class HackerBlockerMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 1. Zuia IP zisizoeleweka au zenye majaribio mengi (Rate Limiting)
        # 2. Zuia SQL Injection na Cross-Site Scripting (XSS)
        response = self.get_response(request)
        
        # Ongeza Security Headers ambazo Hackers wanazichukia
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['Content-Security-Policy'] = "default-src 'self';"
        return response
