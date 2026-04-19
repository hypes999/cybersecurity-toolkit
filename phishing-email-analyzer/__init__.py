"""Phishing Email Analyzer."""

__version__ = "1.0.0"
__author__ = "hypes999"
__description__ = "Phishing Email Analyzer - Extract IoCs and enrich with threat intelligence"

from .analyzer import PhishingEmailAnalyzer, AnalysisConfig, AnalysisResult
from .extractors.headers import extract_headers, EmailHeaders
from .extractors.urls import extract_urls, extract_domains
from .extractors.hashes import extract_hashes

__all__ = [
    "PhishingEmailAnalyzer",
    "AnalysisConfig",
    "AnalysisResult",
    "extract_headers",
    "EmailHeaders",
    "extract_urls",
    "extract_domains",
    "extract_hashes",
]