"""AlienVault OTX (Open Threat Exchange) enrichment module.

This module provides integration with AlienVault OTX for threat intelligence,
including IP reputation, domain analysis, and pulse information.
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import requests


OTX_API_BASE = "https://otx.alienvault.com/api/v1"


@dataclass
class OTXPulse:
    """OTX Pulse/Aware."""

    id: str
    name: str
    description: str
    created: str
    modified: str
    tags: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    attack_ids: List[str] = field(default_factory=list)
    indicator_count: int = 0


@dataclass
class OTXResult:
    """OTX API result."""

    indicator: str
    indicator_type: str
    pulse_count: int
    is_malicious: bool
    sections: Dict[str, Any] = field(default_factory=dict)
    pulses: List[OTXPulse] = field(default_factory=list)
    whois: Optional[str] = None
    geo: Optional[Dict[str, str]] = None
    stats: Optional[Dict[str, Any]] = None


class AlienVaultOTX:
    """Enricher for AlienVault OTX.

    Provides threat intelligence using AlienVault OTX API.
    No API key required for basic IP/domain reputation checks.

    Example:
        >>> enricher = AlienVaultOTX()
        >>> result = enricher.check_ip("1.2.3.4")
        >>> print(result.is_malicious)
        False
    """

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """Initialize enricher.

        Args:
            api_key: Optional API key for extended access
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

        headers = {
            'User-Agent': 'PhishingEmailAnalyzer/1.0'
        }

        if api_key:
            headers['X-OTX-API-KEY'] = api_key

        self.session.headers.update(headers)

    def check_ip(self, ip: str) -> Optional[OTXResult]:
        """Check IP against OTX.

        Args:
            ip: IP address to check

        Returns:
            OTXResult if found, None if not found or error
        """
        try:
            response = self.session.get(
                f"{OTX_API_BASE}/indicators/IPv4/{ip}",
                timeout=self.timeout
            )

            if response.status_code != 200:
                return None

            data = response.json()

            return self._parse_result(ip, 'IPv4', data)

        except (requests.RequestException, json.JSONDecodeError):
            return None

    def check_domain(self, domain: str) -> Optional[OTXResult]:
        """Check domain against OTX.

        Args:
            domain: Domain to check

        Returns:
            OTXResult if found, None if not found or error
        """
        try:
            response = self.session.get(
                f"{OTX_API_BASE}/indicators/domain/{domain}",
                timeout=self.timeout
            )

            if response.status_code != 200:
                return None

            data = response.json()

            return self._parse_result(domain, 'domain', data)

        except (requests.RequestException, json.JSONDecodeError):
            return None

    def check_url(self, url: str) -> Optional[OTXResult]:
        """Check URL against OTX.

        Args:
            url: URL to check

        Returns:
            OTXResult if found, None if not found or error
        """
        try:
            response = self.session.get(
                f"{OTX_API_BASE}/indicators/url/{url}",
                timeout=self.timeout
            )

            if response.status_code != 200:
                return None

            data = response.json()

            return self._parse_result(url, 'url', data)

        except (requests.RequestException, json.JSONDecodeError):
            return None

    def check_hash(self, hash_value: str) -> Optional[OTXResult]:
        """Check file hash (MD5/SHA1/SHA256) against OTX.

        Args:
            hash_value: Hash to check

        Returns:
            OTXResult if found, None if not found or error
        """
        if len(hash_value) not in (32, 40, 64):
            return None

        hash_type = {32: 'MD5', 40: 'SHA1', 64: 'SHA256'}.get(len(hash_value))

        try:
            response = self.session.get(
                f"{OTX_API_BASE}/indicators/file/{hash_type}/{hash_value}",
                timeout=self.timeout
            )

            if response.status_code != 200:
                return None

            data = response.json()

            return self._parse_result(hash_value, 'file', data)

        except (requests.RequestException, json.JSONDecodeError):
            return None

    def _parse_result(self, indicator: str, indicator_type: str, data: Dict) -> OTXResult:
        """Parse OTX API response.

        Args:
            indicator: Indicator value
            indicator_type: Type of indicator
            data: API response data

        Returns:
            OTXResult object
        """
        result = OTXResult(
            indicator=indicator,
            indicator_type=indicator_type,
            pulse_count=0,
            is_malicious=False
        )

        if not data.get('success', True):
            return result

        result.pulse_count = data.get('count', 0)
        result.is_malicious = result.pulse_count > 0

        sections = data.get('sections', {})
        result.sections = sections

        pulses_data = data.get('pulses', [])
        for pulse_data in pulses_data:
            if isinstance(pulse_data, dict) and pulse_data.get('id'):
                result.pulses.append(OTXPulse(
                    id=pulse_data.get('id', ''),
                    name=pulse_data.get('name', ''),
                    description=pulse_data.get('description', ''),
                    created=pulse_data.get('created', ''),
                    modified=pulse_data.get('modified', ''),
                    tags=pulse_data.get('tags', []),
                    malware_families=pulse_data.get('malware_families', []),
                    attack_ids=pulse_data.get('attack_ids', []),
                    indicator_count=pulse_data.get('indicator_count', 0)
                ))

        whois = data.get('whois')
        if whois:
            result.whois = whois.get('whois')

        geo = data.get('geo')
        if geo:
            result.geo = geo

        stats = data.get('stats')
        if stats:
            result.stats = stats

        return result

    def check_indicator(self, indicator: str) -> Optional[OTXResult]:
        """Check any indicator (auto-detect type).

        Args:
            indicator: Indicator to check (IP, domain, URL, or hash)

        Returns:
            OTXResult if found, None if not found or error
        """
        import re

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
            return self.check_ip(indicator)

        if re.match(r'^[0-9a-fA-F]{32}$', indicator):
            return self.check_hash(indicator)

        if re.match(r'^[0-9a-fA-F]{40}$', indicator):
            return self.check_hash(indicator)

        if re.match(r'^[0-9a-fA-F]{64}$', indicator):
            return self.check_hash(indicator)

        if indicator.startswith(('http://', 'https://')):
            return self.check_url(indicator)

        return self.check_domain(indicator)

    def get_reputation_summary(self, result: OTXResult) -> Dict[str, Any]:
        """Get reputation summary.

        Args:
            result: OTXResult to summarize

        Returns:
            Summary dictionary
        """
        return {
            'indicator': result.indicator,
            'indicator_type': result.indicator_type,
            'is_malicious': result.is_malicious,
            'pulse_count': result.pulse_count,
            'has_whois': bool(result.whois),
            'has_geo': bool(result.geo),
            'top_tags': self._get_top_tags(result),
            'top_attack_ids': self._get_top_attack_ids(result)
        }

    def _get_top_tags(self, result: OTXResult, limit: int = 5) -> List[str]:
        """Get top tags from pulses.

        Args:
            result: OTXResult
            limit: Maximum tags to return

        Returns:
            List of tags
        """
        tag_counts = {}

        for pulse in result.pulses:
            for tag in pulse.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)
        return [tag for tag, _ in sorted_tags[:limit]]

    def _get_top_attack_ids(self, result: OTXResult, limit: int = 5) -> List[str]:
        """Get top attack IDs from pulses.

        Args:
            result: OTXResult
            limit: Maximum attack IDs to return

        Returns:
            List of attack IDs
        """
        attack_counts = {}

        for pulse in result.pulses:
            for attack_id in pulse.attack_ids:
                attack_counts[attack_id] = attack_counts.get(attack_id, 0) + 1

        sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
        return [attack_id for attack_id, _ in sorted_attacks[:limit]]

    def close(self) -> None:
        """Close session."""
        self.session.close()