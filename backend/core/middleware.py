import os
import json
import time
from functools import wraps
from django.http import HttpResponseForbidden, JsonResponse
from django.utils.decorators import sync_and_async_middleware
from django.core.cache import cache
from django.conf import settings
import re

class HackerBlockerMiddleware:
    """Advanced Security Middleware for VUNA PESA Platform"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.rate_limit_threshold = 100  # requests per minute
        self.blocked_ips = cache.get('blocked_ips', set())
        self.suspicious_patterns = [
            r"('OR'|'AND'|--|\*|;|UNION|SELECT|DROP|INSERT|UPDATE|DELETE)",
            r"(<script|javascript:|onerror=|onclick=|<iframe)",
            r"(\./|\..\\|%2e%2e)",
            r"(eval|exec|passthru|system|shell_exec)"
        ]

    def __call__(self, request):
        client_ip = self.get_client_ip(request)
        
        # 1. Check if IP is blocked
        if self.is_ip_blocked(client_ip):
            return HttpResponseForbidden(json.dumps({
                'error': 'Access Denied',
                'message': 'Your IP has been blocked due to suspicious activity'
            }), content_type='application/json')

        # 2. Rate limiting check
        if not self.check_rate_limit(client_ip):
            self.block_ip(client_ip)
            return HttpResponseForbidden(json.dumps({
                'error': 'Rate Limit Exceeded',
                'message': 'Too many requests. Please try again later.'
            }), content_type='application/json')

        # 3. Check for SQL Injection & XSS attempts
        if self.contains_malicious_payload(request):
            self.block_ip(client_ip)
            return HttpResponseForbidden(json.dumps({
                'error': 'Malicious Request Detected',
                'message': 'Your request contains suspicious patterns'
            }), content_type='application/json')

        # 4. Validate request headers
        if not self.validate_headers(request):
            return HttpResponseForbidden(json.dumps({
                'error': 'Invalid Headers',
                'message': 'Request headers do not meet security requirements'
            }), content_type='application/json')

        response = self.get_response(request)
        
        # 5. Add Security Headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # 6. Remove sensitive headers
        if 'Server' in response:
            del response['Server']
        
        return response

    def get_client_ip(self, request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def check_rate_limit(self, client_ip):
        """Check if client has exceeded rate limit"""
        cache_key = f'rate_limit_{client_ip}'
        request_count = cache.get(cache_key, 0)
        
        if request_count >= self.rate_limit_threshold:
            return False
        
        cache.set(cache_key, request_count + 1, 60)
        return True

    def is_ip_blocked(self, client_ip):
        """Check if IP is in blocked list"""
        blocked_ips = cache.get('blocked_ips', set())
        return client_ip in blocked_ips

    def block_ip(self, client_ip):
        """Add IP to blocked list (24 hour ban)"""
        blocked_ips = cache.get('blocked_ips', set())
        blocked_ips.add(client_ip)
        cache.set('blocked_ips', blocked_ips, 86400)  # 24 hours

    def contains_malicious_payload(self, request):
        """Detect SQL Injection, XSS, and other attack patterns"""
        payload = str(request.GET) + str(request.POST) + str(request.body)
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        
        return False

    def validate_headers(self, request):
        """Validate required security headers"""
        # Check for suspicious User-Agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        if not user_agent:
            return False
        
        # Block known scanning tools
        scanner_patterns = ['sqlmap', 'nikto', 'nmap', 'masscan', 'nessus']
        for scanner in scanner_patterns:
            if scanner.lower() in user_agent.lower():
                return False
        
        return True


class CORSSecurityMiddleware:
    """Handle CORS with strict security"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.allowed_origins = [
            'https://vuna-pesa.com',
            'https://www.vuna-pesa.com',
            'http://localhost:3000',
            'http://localhost:8000'
        ]

    def __call__(self, request):
        origin = request.META.get('HTTP_ORIGIN')
        
        response = self.get_response(request)
        
        if origin in self.allowed_origins:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS, PUT, DELETE'
            response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            response['Access-Control-Max-Age'] = '3600'
            response['Access-Control-Allow-Credentials'] = 'true'
        
        return response


class AuthenticationMiddleware:
    """Validate authentication tokens and session security"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.public_paths = ['/api/auth/login/', '/api/auth/register/', '/api/auth/forgot-password/']

    def __call__(self, request):
        # Skip auth check for public paths
        if request.path in self.public_paths:
            return self.get_response(request)

        # Check for valid authentication token
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            return JsonResponse({
                'error': 'Unauthorized',
                'message': 'Missing or invalid authorization token'
            }, status=401)

        return self.get_response(request)


class RequestLoggingMiddleware:
    """Log all requests for security audit"""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        log_data = {
            'timestamp': time.time(),
            'method': request.method,
            'path': request.path,
            'ip': request.META.get('REMOTE_ADDR'),
            'user_agent': request.META.get('HTTP_USER_AGENT'),
            'status': 'processing'
        }
        
        response = self.get_response(request)
        
        log_data['status'] = response.status_code
        self.log_request(log_data)
        
        return response

    def log_request(self, data):
        """Log request to file for audit trail"""
        log_file = 'logs/security_audit.log'
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(data) + '\n')
