"""Unshield - phishing detector for links, messages, emails and QR codes."""
from .models import Finding, Result
from .url_analyzer import analyze_url
from .text_analyzer import analyze_text
from .email_analyzer import analyze_email
from .qr_analyzer import analyze_qr_image, analyze_qr_payload

__all__ = [
    "Finding", "Result", "analyze_url", "analyze_text", "analyze_email",
    "analyze_qr_image", "analyze_qr_payload",
]
__version__ = "1.0.0"
