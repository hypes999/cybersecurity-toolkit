"""HTML content analyzer for phishing detection.

This module provides functionality to analyze HTML content in emails
for suspicious patterns, malicious scripts, and obfuscated elements.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from html.parser import HTMLParser


@dataclass
class HTMLAnalysis:
    """HTML analysis result."""

    has_html: bool = False
    suspicious_scripts: List[str] = field(default_factory=list)
    iframes: List[str] = field(default_factory=list)
    hidden_elements: List[str] = field(default_factory=list)
    obfuscated_links: List[str] = field(default_factory=list)
    forms: List[Dict[str, str]] = field(default_factory=list)
    external_resources: List[str] = field(default_factory=list)
    data_uris: List[str] = field(default_factory=list)
    suspicious_events: List[str] = field(default_factory=list)
    display_none_elements: List[str] = field(default_factory=list)
    redirect_links: List[str] = field(default_factory=list)
    risk_score: int = 0


class HTMLPhishingDetector(HTMLParser):
    """HTML parser for phishing detection."""

    def __init__(self):
        super().__init__()
        self.analysis = HTMLAnalysis()
        self.current_tag = None
        self.current_attrs = []
        self.body_started = False

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag
        self.current_attrs = attrs
        self.analysis.has_html = True

        attrs_dict = dict(attrs)

        if tag == 'script':
            src = attrs_dict.get('src', '')
            if src:
                self.analysis.suspicious_scripts.append(src)
            else:
                self.analysis.suspicious_scripts.append('<inline script>')

        elif tag == 'iframe':
            src = attrs_dict.get('src', '')
            self.analysis.iframes.append(src or '<no-src>')

        elif tag == 'form':
            action = attrs_dict.get('action', '')
            method = attrs_dict.get('method', 'get')
            self.analysis.forms.append({'action': action, 'method': method})

        elif tag == 'a':
            href = attrs_dict.get('href', '')
            text = attrs_dict.get('data-text', '')

            if href and text and href != text:
                self.analysis.obfuscated_links.append(f'Display: {text} -> URL: {href}')

            if href and any(x in href.lower() for x in ['redirect', 'url=', 'link=', 'go=']):
                self.analysis.redirect_links.append(href)

        elif tag == 'img':
            src = attrs_dict.get('src', '')
            if src and src.startswith('data:'):
                self.analysis.data_uris.append('img data URI')

        elif tag in ('div', 'span', 'p', 'td', 'table'):
            style = attrs_dict.get('style', '').lower()
            if 'display:none' in style or 'visibility:hidden' in style:
                style_val = attrs_dict.get('style', '')
                self.analysis.display_none_elements.append(f'<{tag} style="{style_val}">')

        for attr, value in attrs:
            if attr.startswith('on'):
                self.analysis.suspicious_events.append(f'{attr}="{value[:50]}"')

        for attr, value in attrs:
            if attr == 'src' and value and value.startswith('http'):
                self.analysis.external_resources.append(value)
            elif attr == 'href' and value and value.startswith('http'):
                self.analysis.external_resources.append(value)

    def handle_endtag(self, tag):
        self.current_tag = None

    def handle_data(self, data):
        pass


def analyze_html_content(html_content: str) -> HTMLAnalysis:
    """Analyze HTML content for phishing indicators.

    Args:
        html_content: HTML content string

    Returns:
        HTMLAnalysis object with findings
    """
    if not html_content or not html_content.strip():
        return HTMLAnalysis()

    detector = HTMLPhishingDetector()

    try:
        detector.feed(html_content)
    except Exception:
        pass

    analysis = detector.analysis

    analysis.risk_score = 0

    if analysis.suspicious_scripts:
        analysis.risk_score += 3
    if analysis.iframes:
        analysis.risk_score += 3
    if analysis.obfuscated_links:
        analysis.risk_score += 4
    if analysis.forms:
        analysis.risk_score += 2
        for form in analysis.forms:
            if form['action'] and not form['action'].startswith('http'):
                analysis.risk_score += 1
    if analysis.suspicious_events:
        analysis.risk_score += 3
    if analysis.display_none_elements:
        analysis.risk_score += 2
    if analysis.redirect_links:
        analysis.risk_score += 2

    return analysis


def extract_attachments_from_email(email_content: str) -> List[Dict[str, Any]]:
    """Extract attachment information from email content.

    Args:
        email_content: Raw email content

    Returns:
        List of attachment dictionaries
    """
    attachments = []

    attachment_pattern = re.compile(
        r'Content-Type:\s*.*?;\s*name=["\']?([^"\'>\s]+)',
        re.IGNORECASE
    )

    for match in attachment_pattern.finditer(email_content):
        filename = match.group(1)
        if filename:
            ext = filename.split('.')[-1].lower() if '.' in filename else ''

            risk = 0
            suspicious_extensions = ['exe', 'scr', 'bat', 'cmd', 'vbs', 'js', 'jar', 'zip', 'rar', '7z']
            if ext in suspicious_extensions:
                risk = 3 if ext in ('exe', 'scr', 'bat', 'vbs', 'js', 'jar') else 2

            attachments.append({
                'filename': filename,
                'extension': ext,
                'suspicious': ext in suspicious_extensions,
                'risk_score': risk
            })

    return attachments


def check_reply_to_mismatch(headers: Dict[str, str]) -> Dict[str, Any]:
    """Check if Reply-To differs from From address.

    Args:
        headers: Email headers dictionary

    Returns:
        Dictionary with mismatch information
    """
    from_addr = headers.get('from', '')
    reply_to = headers.get('reply_to', '')

    if not from_addr or not reply_to:
        return {'mismatch': False}

    from_email = extract_email_from_header(from_addr)
    reply_email = extract_email_from_header(reply_to)

    mismatch = from_email.lower() != reply_email.lower() if (from_email and reply_email) else False

    return {
        'mismatch': mismatch,
        'from_email': from_email,
        'reply_to_email': reply_email,
    }


def extract_email_from_header(header_value: str) -> Optional[str]:
    """Extract email address from header value.

    Args:
        header_value: Header value string

    Returns:
        Email address or None
    """
    match = re.search(r'<(.+?)>', header_value)
    if match:
        return match.group(1)

    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_value)
    if match:
        return match.group(0)

    return None


def check_sender_domain_quality(sender_email: str) -> Dict[str, Any]:
    """Analyze sender domain for suspicious patterns.

    Args:
        sender_email: Sender email address

    Returns:
        Dictionary with domain analysis
    """
    result = {
        'domain': '',
        'suspicious': False,
        'reasons': [],
        'risk_score': 0
    }

    if not sender_email or '@' not in sender_email:
        return result

    try:
        email_part = sender_email.split('@')[-1] if '@' in sender_email else sender_email

        domain = email_part
        tld = ''

        if '.' in email_part:
            parts = email_part.rsplit('.', 1)
            domain = parts[0]
            tld = parts[1] if len(parts) > 1 else ''

        result['domain'] = email_part

        suspicious_tlds = ['xyz', 'top', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'link', 'work', 'loan', 'online', 'site', 'website', 'info']
        if tld.lower() in suspicious_tlds:
            result['suspicious'] = True
            result['reasons'].append(f'Suspicious TLD: {tld}')
            result['risk_score'] += 2

        if re.search(r'\d{4,}', domain):
            result['suspicious'] = True
            result['reasons'].append('Domain contains consecutive numbers')
            result['risk_score'] += 2

        if len(domain) > 20:
            result['suspicious'] = True
            result['reasons'].append('Unusually long domain')
            result['risk_score'] += 1

        if 'mail' in domain.lower() or 'email' in domain.lower():
            result['suspicious'] = True
            result['reasons'].append('Domain contains mail/email keywords')
            result['risk_score'] += 1

    except Exception:
        pass

    return result