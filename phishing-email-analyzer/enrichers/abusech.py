"""Abuse.ch enrichment module.

This module provides integration with Abuse.ch services:
- URLhaus: Malicious URL database
- MalwareBazaar: Malware sample database
- FakeBot: Malware with C2 communication detection
- SSL Blacklist: Malicious SSL certificates
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
import requests


ABUSE_CH_API_BASE = "https://urlhaus-api.abuse.ch/v1"
MALWAREBAZAAR_API_BASE = "https://mb-api.abuse.ch/api/v1"


@dataclass
class URLhausResult:
    """URLhaus API result."""

    url: str
    threat: str
    url_status: str
    date_added: str
    last_online: str
    api_threat: str
    tags: List[str] = field(default_factory=list)
    urlhaus_link: str = ""
    reporter: str = ""
    is_malware: bool = False
    is_phishing: bool = False


@dataclass
class MalwareBazaarResult:
    """MalwareBazaar API result."""

    sha256_hash: str
    md5_hash: str
    sha1_hash: str
    file_type: str
    file_type_extension: str
    file_size: int
    first_seen: str
    last_seen: str
    delivery_method: str
    malware_names: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    signatures: List[str] = field(default_factory=list)
    is_malware: bool = False


class AbuseChEnricher:
    """Enricher for Abuse.ch services.

    Provides threat intelligence enrichment using free Abuse.ch APIs.
    No API key required for basic usage.

    Example:
        >>> enricher = AbuseChEnricher()
        >>> result = enricher.check_url("https://malicious-site.com/payload.exe")
        >>> print(result.threat)
        malware_download
    """

    def __init__(self, timeout: int = 30):
        """Initialize enricher.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PhishingEmailAnalyzer/1.0'
        })

    def check_url(self, url: str) -> Optional[URLhausResult]:
        """Check URL against URLhaus database.

        Args:
            url: URL to check

        Returns:
            URLhausResult if found, None if not found or error
        """
        try:
            response = self.session.post(
                f"{ABUSE_CH_API_BASE}/url/",
                data={'url': url},
                timeout=self.timeout
            )

            if response.status_code != 200:
                return None

            data = response.json()

            if data.get('query_status') != 'no_match':
                return None

            url_info = data.get('url', {})

            return URLhausResult(
                url=url,
                threat=url_info.get('threat', 'unknown'),
                url_status=url_info.get('url_status', 'unknown'),
                date_added=url_info.get('date_added', ''),
                last_online=url_info.get('last_online', ''),
                api_threat=url_info.get('api_threat', 'unknown'),
                tags=url_info.get('tags', []),
                urlhaus_link=url_info.get('urlhaus_link', ''),
                reporter=url_info.get('reporter', ''),
                is_malware=url_info.get('threat') == 'malware_download',
                is_phishing=url_info.get('threat') == 'phishing'
            )

        except (requests.RequestException, json.JSONDecodeError):
            return None

    def check_domain(self, domain: str) -> List[URLhausResult]:
        """Check all URLs for a domain in URLhaus.

        Args:
            domain: Domain to check

        Returns:
            List of URLhausResult for URLs from this domain
        """
        results = []

        try:
            response = self.session.post(
                f"{ABUSE_CH_API_BASE}/domain/",
                data={'domain': domain},
                timeout=self.timeout
            )

            if response.status_code != 200:
                return results

            data = response.json()

            if data.get('query_status') != 'no_match':
                return results

            urls = data.get('urls', [])

            for url_info in urls:
                results.append(URLhausResult(
                    url=url_info.get('url', ''),
                    threat=url_info.get('threat', 'unknown'),
                    url_status=url_info.get('url_status', 'unknown'),
                    date_added=url_info.get('date_added', ''),
                    last_online=url_info.get('last_online', ''),
                    api_threat=url_info.get('api_threat', 'unknown'),
                    tags=url_info.get('tags', []),
                    urlhaus_link=url_info.get('urlhaus_link', ''),
                    reporter=url_info.get('reporter', ''),
                    is_malware=url_info.get('threat') == 'malware_download',
                    is_phishing=url_info.get('threat') == 'phishing'
                ))

        except (requests.RequestException, json.JSONDecodeError):
            pass

        return results

    def check_hash(self, sha256_hash: str) -> Optional[MalwareBazaarResult]:
        """Check hash against MalwareBazaar.

        Args:
            sha256_hash: SHA256 hash to check

        Returns:
            MalwareBazaarResult if found, None if not found or error
        """
        try:
            response = self.session.post(
                f"{MALWAREBAZAAR_API_BASE}/hash",
                json={
                    'hash': sha256_hash
                },
                timeout=self.timeout
            )

            if response.status_code != 200:
                return None

            data = response.json()

            if data.get('query_status') != 'ok':
                return None

            hashes = data.get('hashes', [])

            if not hashes:
                return None

            file_info = hashes[0]

            return MalwareBazaarResult(
                sha256_hash=file_info.get('sha256_hash', ''),
                md5_hash=file_info.get('md5_hash', ''),
                sha1_hash=file_info.get('sha1_hash', ''),
                file_type=file_info.get('file_type', ''),
                file_type_extension=file_info.get('file_type_extension', ''),
                file_size=int(file_info.get('file_size', 0)),
                first_seen=file_info.get('first_seen', ''),
                last_seen=file_info.get('last_seen', ''),
                delivery_method=file_info.get('delivery_method', ''),
                malware_names=file_info.get('malware_names', []),
                tags=file_info.get('tags', []),
                signatures=file_info.get('signatures', []),
                is_malware=True
            )

        except (requests.RequestException, json.JSONDecodeError):
            return None

    def check_urls_batch(self, urls: List[str]) -> Dict[str, Optional[URLhausResult]]:
        """Check multiple URLs at once.

        Args:
            urls: List of URLs to check

        Returns:
            Dictionary mapping URL to result
        """
        results = {}

        for url in urls:
            result = self.check_url(url)
            results[url] = result

        return results

    def get_threat_summary(self, results: List[URLhausResult]) -> Dict[str, Any]:
        """Get summary of threat results.

        Args:
            results: List of URLhausResult

        Returns:
            Summary dictionary
        """
        summary = {
            'total_urls': len(results),
            'malicious': 0,
            'phishing': 0,
            'safe': 0,
            'suspicious': 0,
            'threats': set(),
            'tags': set()
        }

        for result in results:
            if result.threat == 'malware_download':
                summary['malicious'] += 1
                summary['threats'].add('malware')
            elif result.threat == 'phishing':
                summary['phishing'] += 1
                summary['threats'].add('phishing')
            elif result.url_status == 'offline':
                summary['safe'] += 1
            else:
                summary['suspicious'] += 1

            summary['tags'].update(result.tags)

        summary['threats'] = list(summary['threats'])
        summary['tags'] = list(summary['tags'])

        return summary

    def close(self) -> None:
        """Close session."""
        self.session.close()