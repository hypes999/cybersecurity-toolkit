"""URL and domain extraction module.

This module provides functionality to extract URLs and domains from email content,
including HTML parsing and domain analysis.
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse


@dataclass
class ExtractedURL:
    """Extracted URL with metadata."""

    url: str
    domain: str
    scheme: str
    path: Optional[str] = None
    params: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None
    is_shortened: bool = False
    is_suspicious: bool = False


@dataclass
class ExtractedDomain:
    """Extracted domain with analysis."""

    domain: str
    tld: str
    sld: Optional[str] = None
    subdomain: Optional[str] = None
    is_public: bool = True
    has_numbers: bool = False
    is_ip: bool = False
    suspicious_patterns: List[str] = field(default_factory=list)


def extract_urls(text: str) -> List[ExtractedURL]:
    """Extract all URLs from text content.

    Args:
        text: Text content to scan

    Returns:
        List of ExtractedURL objects

    Example:
        >>> text = "Visit https://example.com/click?id=123"
        >>> urls = extract_urls(text)
        >>> print(urls[0].domain)
        example.com
    """
    urls = []
    seen_urls = set()

    url_pattern = re.compile(
        r'((?:https?|ftp)://[^\s<>"\']+|http://[^\s<>"\']+)'
    )

    private_ip_pattern = re.compile(
        r'(?:https?|http)://(?:10\.\d+|192\.168\.|172\.(?:1[6-9]|2\d|3[01])|127\.|0\.)'
    )

    for match in url_pattern.finditer(text):
        url_str = match.group(1) if match.lastindex else match.group(0)
        if not url_str:
            url_str = match.group(0)

        if url_str.startswith('mailto:'):
            continue

        if private_ip_pattern.search(url_str):
            continue

        if url_str in seen_urls:
            continue
        seen_urls.add(url_str)

        try:
            parsed = urlparse(url_str)
        except:
            continue

        if not parsed.scheme or parsed.scheme not in ('http', 'https', 'ftp'):
            continue

        if not parsed.netloc:
            continue

        if '.' not in parsed.netloc:
            continue

        tld = parsed.netloc.split('.')[-1] if '.' in parsed.netloc else ''
        if len(tld) < 2 or len(tld) > 12:
            continue

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc):
            if parsed.netloc.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.',
                      '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
                      '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
                      '172.28.', '172.29.', '172.30.', '172.31.', '0.', '255.')):
                continue

        url_obj = ExtractedURL(
            url=url_str,
            domain=parsed.netloc.lower(),
            scheme=parsed.scheme,
            path=parsed.path or None,
            params=parsed.params or None,
            query=parsed.query or None,
            fragment=parsed.fragment or None,
            is_shortened=is_shortened_url(parsed.netloc),
            is_suspicious=is_suspicious_url(parsed.netloc)
        )

        urls.append(url_obj)

    return urls


def extract_domains(text: str) -> List[ExtractedDomain]:
    """Extract and analyze all domains from text content.

    Args:
        text: Text content to scan

    Returns:
        List of ExtractedDomain objects

    Example:
        >>> text = "Email from test.example.com and 192.168.1.1"
        >>> domains = extract_domains(text)
        >>> print([d.domain for d in domains])
        ['example.com']
    """
    urls = extract_urls(text)
    domains = []
    seen_domains = set()

    ip_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )

    for match in ip_pattern.finditer(text):
        ip = match.group(0)
        if ip.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.',
                      '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
                      '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
                      '172.28.', '172.29.', '172.30.', '172.31.')):
            continue

        if ip not in seen_domains:
            seen_domains.add(ip)
            domains.append(ExtractedDomain(
                domain=ip,
                tld='ip',
                sld=ip,
                is_public=False,
                is_ip=True
            ))

    for url in urls:
        domain = url.domain

        if not domain or '.' not in domain:
            continue

        if domain in seen_domains:
            continue
        seen_domains.add(domain)

        if '/' in domain or domain.endswith(('.php', '.html', '.htm', '.asp', '.aspx', '.jsp')):
            continue

        parsed_domain = analyze_domain(domain)
        if not parsed_domain.tld or len(parsed_domain.tld) < 2 or len(parsed_domain.tld) > 10:
            continue

        domains.append(parsed_domain)

    return domains


def analyze_domain(domain: str) -> ExtractedDomain:
    """Analyze a single domain for suspicious patterns.

    Args:
        domain: Domain to analyze

    Returns:
        ExtractedDomain object with analysis

    Example:
        >>> domain = analyze_domain("example.com")
        >>> domain.is_public
        True
    """
    suspicious = []

    if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', domain):
        return ExtractedDomain(
            domain=domain,
            tld='ip',
            sld=domain,
            is_public=False,
            is_ip=True
        )

    parts = domain.split('.')
    tld = parts[-1] if len(parts) > 1 else parts[0]
    sld = parts[-2] if len(parts) > 1 else parts[0]
    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else None

    has_numbers = bool(re.search(r'\d', domain))
    is_ip = bool(re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', domain))

    suspicious_patterns = [
        (r'\d{4,}', 'consecutive_numbers'),
        (r'-(?:login|signin|account|verify|secure|update|confirm|bank|pay|suporte|ajuda|delivery|track|order|billing|payment|refund|wallet|support)', 'suspicious_keyword'),
        (r'(?:[a-z]{10,})\.(?:com|net|org)', 'long_subdomain'),
        (r'(?:[0-9]{4,})\.(?:com|net|org)', 'numeric_domain'),
        (r'(?:paypal|amazon|microsoft|google|apple|facebook|netflix|bank|banco|netsuite|secure|verify|irs|tax|customs|ebay|linkedin|instagram|whatsapp|netflix|dropbox|docuSign|adobe)\d', 'brand_spoof'),
        (r'(?:paypal|amazon|microsoft|google|apple|facebook|netflix|bank|banco|netsuite|secure|verify|irs|tax|customs|ebay|linkedin)\.[a-z]{2,}', 'brand_in_domain'),
        (r'(?:[0-9]{3,})\.(?:com|net|org|info|online)', 'numeric_tld'),
    ]

    for pattern, desc in suspicious_patterns:
        if re.search(pattern, domain, re.IGNORECASE):
            suspicious.append(desc)

    return ExtractedDomain(
        domain=domain,
        tld=tld,
        sld=sld,
        subdomain=subdomain,
        is_public=tld.lower() not in ('localhost', 'local', 'test', 'example'),
        has_numbers=has_numbers,
        is_ip=is_ip,
        suspicious_patterns=suspicious
    )


def is_shortened_url(domain: str) -> bool:
    """Check if domain is a known URL shortener.

    Args:
        domain: Domain to check

    Returns:
        True if domain is a known shortener
    """
    shorteners = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'j.mp', 'tiny.cc', 'lnkd.in', 'db.tt',
        'qr.ae', 'cur.lv', 'ity.im', 'q.gs', 'po.st', 'su.pr',
        'owly.eu', '威锋.中国', 'dl.gd', 'href.li', '3.ly'
    }

    domain_lower = domain.lower()
    return any(shortener in domain_lower for shortener in shorteners)


def is_suspicious_url(domain: str) -> bool:
    """Check if URL shows suspicious patterns.

    Args:
        domain: Domain to check

    Returns:
        True if URL appears suspicious
    """
    suspicious = [
        re.compile(r'\d{6,}'),
        re.compile(r'(?:login|signin|verify|secure|account|update|refund|wallet|support)[-.@]'),
        re.compile(r'(?:paypal|amazon|microsoft|google|apple|netflix|bank|irs|tax|customs|ebay|linkedin)[-.0-9]'),
        re.compile(r'(?:cf|php|html?|asp|cgi)\d'),
        re.compile(r'(?:secure|login|verify|account)[0-9]'),
    ]

    for pattern in suspicious:
        if pattern.search(domain):
            return True

    return False


def extract_emails(text: str) -> List[str]:
    """Extract email addresses from text.

    Args:
        text: Text to scan

    Returns:
        List of email addresses
    """
    email_pattern = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )

    emails = list(set(email_pattern.findall(text)))
    return sorted(emails)


def extract_urls_with_context(text: str, context_chars: int = 50) -> List[Dict[str, any]]:
    """Extract URLs with surrounding context.

    Args:
        text: Text to scan
        context_chars: Number of characters to include before/after

    Returns:
        List of dictionaries with URL and context
    """
    urls = extract_urls(text)
    results = []

    for url_obj in urls:
        match = re.search(re.escape(url_obj.url), text)
        if match:
            start = max(0, match.start() - context_chars)
            end = min(len(text), match.end() + context_chars)
            context = text[start:end].replace('\n', ' ').strip()

            results.append({
                'url': url_obj.url,
                'domain': url_obj.domain,
                'scheme': url_obj.scheme,
                'context': context,
                'is_shortened': url_obj.is_shortened,
                'is_suspicious': url_obj.is_suspicious
            })

    return results