"""Stable ASGI entrypoint for PhishingGuard Final.

The Docker build restores the verified scanner/model baseline as app.py and
phishing_url_detector.keras. This module deliberately keeps one unambiguous
production entrypoint: main:app.
"""

from app import app

__all__ = ["app"]
