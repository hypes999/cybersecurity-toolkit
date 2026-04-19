"""VirusTotal enrichment module.

This module provides integration with VirusTotal API v3 for threat intelligence.
API key is required - get free key at https://www.virustotal.com
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import requests


VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class VTResult:
    """VirusTotal API result."""

    indicator: str
    indicator_type: str
    last_analysis_stats: Dict[str, int] = field(default_factory=dict)
    last_analysis_results: Dict[str, Any] = field(default_factory=dict)
    is_malicious: bool = False
    malware_names: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    votes: Dict[str, int] = field(default_factory=dict)
    community_score: int = 0
    reputation: int = 0
    whois: Optional[str] = None
    html_url: str = ""
    error: Optional[str] = None


@dataclass
class VTFileResult(VTResult):
    """VirusTotal file analysis result."""

    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    file_type: Optional[str] = None
    file_size: int = 0
    first_submission_date: Optional[str] = None
    last_analysis_date: Optional[str] = None
    last_modification_date: Optional[str] = None


@dataclass
class VTURLResult(VTResult):
    """VirusTotal URL analysis result."""

    url: str = ""
    final_url: Optional[str] = None
    redirecting_entries: List[str] = field(default_factory=list)
    unicast_https_links: List[str] = field(default_factory=list)


@dataclass
class VTDomainResult(VTResult):
    """VirusTotal domain analysis result."""

    domain: str = ""
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    last_update_date: Optional[str] = None
    total_submissions: int = 0


class VirusTotalEnricher:
    """Enricher for VirusTotal.

    Provides threat intelligence using VirusTotal API v3.
    Requires API key - get free key at https://www.virustotal.com

    Example:
        >>> enricher = VirusTotalEnricher(api_key="your-api-key")
        >>> result = enricher.check_url("https://malicious-site.com")
        >>> print(result.is_malicious)
        True
    """

    def __init__(self, api_key: str, timeout: int = 30):
        """Initialize enricher.

        Args:
            api_key: VirusTotal API key
            timeout: Request timeout in seconds
        """
        if not api_key:
            raise ValueError("API key is required for VirusTotal enricher")

        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

        self.session.headers.update({
            'x-apikey': api_key,
            'User-Agent': 'PhishingEmailAnalyzer/1.0'
        })

    def check_url(self, url: str) -> VTURLResult:
        """Check URL against VirusTotal.

        Args:
            url: URL to check

        Returns:
            VTURLResult with analysis
        """
        result = VTURLResult(
            indicator=url,
            indicator_type='url',
            url=url
        )

        try:
            response = self.session.get(
                f"{VIRUSTOTAL_API_BASE}/urls",
                params={'url': url},
                timeout=self.timeout
            )

            if response.status_code == 404:
                result.error = "URL not found in VirusTotal"
                return result

            if response.status_code != 200:
                result.error = f"API error: {response.status_code}"
                return result

            data = response.json()

            if 'data' not in data or not data['data']:
                result.error = "No data in response"
                return result

            attributes = data['data'].get('attributes', {})

            result.last_analysis_stats = attributes.get('last_analysis_stats', {})
            result.last_analysis_results = attributes.get('last_analysis_results', {})
            result.is_malicious = result.last_analysis_stats.get('malicious', 0) > 0
            result.votes = attributes.get('votes', {})
            result.community_score = attributes.get('community_score', 0)
            result.html_url = f"https://www.virustotal.com/g/url/{url}"

            stats = result.last_analysis_stats
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)

            if malicious_count > 0 or suspicious_count > 0:
                result.is_malicious = True

        except requests.RequestException as e:
            result.error = f"Request error: {str(e)}"
        except json.JSONDecodeError:
            result.error = "Invalid JSON response"

        return result

    def check_ip(self, ip: str) -> VTResult:
        """Check IP against VirusTotal.

        Args:
            ip: IP address to check

        Returns:
            VTResult with analysis
        """
        result = VTResult(
            indicator=ip,
            indicator_type='ip'
        )

        try:
            response = self.session.get(
                f"{VIRUSTOTAL_API_BASE}/ip_addresses/{ip}",
                timeout=self.timeout
            )

            if response.status_code == 404:
                result.error = "IP not found"
                return result

            if response.status_code != 200:
                result.error = f"API error: {response.status_code}"
                return result

            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})

            result.last_analysis_stats = attributes.get('last_analysis_stats', {})
            result.last_analysis_results = attributes.get('last_analysis_results', {})
            result.is_malicious = result.last_analysis_stats.get('malicious', 0) > 0
            result.votes = attributes.get('votes', {})
            result.community_score = attributes.get('community_score', 0)
            result.html_url = f"https://www.virustotal.com/g/ip-address/{ip}"

        except requests.RequestException as e:
            result.error = f"Request error: {str(e)}"
        except json.JSONDecodeError:
            result.error = "Invalid JSON response"

        return result

    def check_domain(self, domain: str) -> VTDomainResult:
        """Check domain against VirusTotal.

        Args:
            domain: Domain to check

        Returns:
            VTDomainResult with analysis
        """
        result = VTDomainResult(
            indicator=domain,
            indicator_type='domain',
            domain=domain
        )

        try:
            response = self.session.get(
                f"{VIRUSTOTAL_API_BASE}/domains/{domain}",
                timeout=self.timeout
            )

            if response.status_code == 404:
                result.error = "Domain not found"
                return result

            if response.status_code != 200:
                result.error = f"API error: {response.status_code}"
                return result

            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})

            result.last_analysis_stats = attributes.get('last_analysis_stats', {})
            result.last_analysis_results = attributes.get('last_analysis_results', {})
            result.is_malicious = result.last_analysis_stats.get('malicious', 0) > 0
            result.votes = attributes.get('votes', {})
            result.community_score = attributes.get('community_score', 0)
            result.html_url = f"https://www.virustotal.com/g/domain/{domain}"

            whois = attributes.get('whois', {})
            result.registrar = whois.get('registrar')
            result.creation_date = whois.get('creation_date')
            result.expiration_date = whois.get('expiration_date')
            result.total_submissions = attributes.get('total_submissions', 0)

        except requests.RequestException as e:
            result.error = f"Request error: {str(e)}"
        except json.JSONDecodeError:
            result.error = "Invalid JSON response"

        return result

    def check_hash(self, hash_value: str) -> VTFileResult:
        """Check file hash against VirusTotal.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash

        Returns:
            VTFileResult with analysis
        """
        result = VTFileResult(
            indicator=hash_value,
            indicator_type='file'
        )

        try:
            response = self.session.get(
                f"{VIRUSTOTAL_API_BASE}/files/{hash_value}",
                timeout=self.timeout
            )

            if response.status_code == 404:
                result.error = "File not found"
                return result

            if response.status_code != 200:
                result.error = f"API error: {response.status_code}"
                return result

            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})

            result.sha256 = attributes.get('sha256', '')
            result.md5 = attributes.get('md5', '')
            result.sha1 = attributes.get('sha1', '')
            result.file_type = attributes.get('type_description')
            result.file_size = attributes.get('size', 0)

            result.last_analysis_stats = attributes.get('last_analysis_stats', {})
            result.last_analysis_results = attributes.get('last_analysis_results', {})
            result.is_malicious = result.last_analysis_stats.get('malicious', 0) > 0
            result.votes = attributes.get('votes', {})
            result.community_score = attributes.get('community_score', 0)

            result.first_submission_date = attributes.get('first_submission_date')
            result.last_analysis_date = attributes.get('last_analysis_date')
            result.last_modification_date = attributes.get('last_modification_date')

            result.malware_names = []
            last_analysis = result.last_analysis_results
            for engine_name, engine_result in last_analysis.items():
                if isinstance(engine_result, dict):
                    category = engine_result.get('category', '')
                    if category == 'malicious':
                        result.malware_names.append(engine_result.get('result', ''))

            result.tags = attributes.get('tags', [])
            result.html_url = f"https://www.virustotal.com/g/file/{hash_value}"

        except requests.RequestException as e:
            result.error = f"Request error: {str(e)}"
        except json.JSONDecodeError:
            result.error = "Invalid JSON response"

        return result

    def check_indicator(self, indicator: str) -> VTResult:
        """Check any indicator (auto-detect type).

        Args:
            indicator: Indicator to check

        Returns:
            VTResult with analysis
        """
        import re

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
            return self.check_ip(indicator)

        if len(indicator) in (32, 40, 64) and re.match(r'^[0-9a-fA-F]+$', indicator):
            return self.check_hash(indicator)

        if indicator.startswith(('http://', 'https://')):
            return self.check_url(indicator)

        return self.check_domain(indicator)

    def get_analysis_summary(self, result: VTResult) -> Dict[str, Any]:
        """Get analysis summary.

        Args:
            result: VTResult to summarize

        Returns:
            Summary dictionary
        """
        stats = result.last_analysis_stats

        return {
            'indicator': result.indicator,
            'indicator_type': result.indicator_type,
            'is_malicious': result.is_malicious,
            'malicious_count': stats.get('malicious', 0),
            'suspicious_count': stats.get('suspicious', 0),
            'undetected_count': stats.get('undetected', 0),
            'harmless_count': stats.get('harmless', 0),
            'community_score': result.community_score,
            'votes': result.votes,
            'html_url': result.html_url,
            'error': result.error
        }

    def close(self) -> None:
        """Close session."""
        self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()