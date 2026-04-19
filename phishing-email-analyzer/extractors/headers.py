"""Email header extraction and analysis module.

This module provides functionality to extract and analyze email headers,
including SPF, DKIM, and DMARC validation results.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List


@dataclass
class EmailHeaders:
    """Parsed email headers."""

    raw_headers: Dict[str, str] = field(default_factory=dict)
    from_addr: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    received: List[str] = field(default_factory=list)
    authentication_results: Optional[str] = None
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    x_mailer: Optional[str] = None
    x_originating_ip: Optional[str] = None
    content_type: Optional[str] = None
    mime_version: Optional[str] = None
    x_priority: Optional[str] = None


def extract_headers(email_content: str) -> EmailHeaders:
    """Extract all relevant headers from raw email content.

    Args:
        email_content: Raw email content (headers + body)

    Returns:
        EmailHeaders object with parsed headers

    Example:
        >>> content = "From: sender@example.com\\nSubject: Test\\n..."
        >>> headers = extract_headers(content)
        >>> print(headers.from_addr)
        sender@example.com
    """
    headers = EmailHeaders()
    raw_headers_dict = {}

    lines = email_content.split('\n')
    current_header = None
    header_value_lines = []

    for line in lines:
        if not line.strip():
            break

        match = re.match(r'^([\w-]+):\s*(.*)$', line)
        if match:
            if current_header and header_value_lines:
                header_key = current_header.lower()
                header_value = ' '.join(header_value_lines).strip()
                raw_headers_dict[header_key] = header_value

                process_header(headers, header_key, header_value)

            current_header = match.group(1)
            header_value_lines = [match.group(2)]
        elif current_header and line.startswith((' ', '\t')):
            header_value_lines.append(line.strip())

    if current_header and header_value_lines:
        header_key = current_header.lower()
        header_value = ' '.join(header_value_lines).strip()
        raw_headers_dict[header_key] = header_value
        process_header(headers, header_key, header_value)

    headers.raw_headers = raw_headers_dict
    return headers


def process_header(headers: EmailHeaders, key: str, value: str) -> None:
    """Process individual header and populate EmailHeaders object.

    Args:
        headers: EmailHeaders object to populate
        key: Header name (lowercase)
        value: Header value
    """
    key_map = {
        'from': 'from_addr',
        'reply-to': 'reply_to',
        'return-path': 'return_path',
        'subject': 'subject',
        'date': 'date',
        'message-id': 'message_id',
        'received': 'received',
        'authentication-results': 'authentication_results',
        'x-mailer': 'x_mailer',
        'x-originating-ip': 'x_originating_ip',
        'content-type': 'content_type',
        'mime-version': 'mime_version',
        'x-priority': 'x_priority',
    }

    if key == 'received':
        headers.received.append(value)
    elif key in key_map:
        attr = key_map[key]
        setattr(headers, attr, value)

    if key == 'authentication-results':
        parse_authentication_results(headers, value)


def parse_authentication_results(headers: EmailHeaders, auth_results: str) -> None:
    """Parse Authentication-Results header for SPF/DKIM/DMARC status.

    Args:
        headers: EmailHeaders object to populate
        auth_results: Raw Authentication-Results header value
    """
    spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', auth_results, re.IGNORECASE)
    if spf_match:
        headers.spf_result = spf_match.group(1).lower()

    dkim_match = re.search(r'dkim=(pass|fail|none|temperror|permerror)', auth_results, re.IGNORECASE)
    if dkim_match:
        headers.dkim_result = dkim_match.group(1).lower()

    dmarc_match = re.search(r'dmarc=(pass|fail|none)', auth_results, re.IGNORECASE)
    if dmarc_match:
        headers.dmarc_result = dmarc_match.group(1).lower()


def parse_email_headers(email_content: str) -> Dict[str, str]:
    """Simple wrapper for backward compatibility.

    Args:
        email_content: Raw email content

    Returns:
        Dictionary of parsed headers
    """
    headers = extract_headers(email_content)
    return headers.raw_headers


def check_spf(headers: EmailHeaders) -> Dict[str, any]:
    """Analyze SPF authentication result.

    Args:
        headers: Parsed email headers

    Returns:
        Dictionary with SPF analysis
    """
    result = {
        'status': headers.spf_result,
        'passed': False,
        'warning': None,
        'details': None
    }

    if headers.spf_result == 'pass':
        result['passed'] = True
        result['details'] = 'SPF validation passed'
    elif headers.spf_result == 'fail':
        result['warning'] = 'SPF validation failed - possible spoofing'
        result['details'] = 'Email sender IP does not match authorized servers'
    elif headers.spf_result == 'softfail':
        result['warning'] = 'SPF softfail - sender not authorized'
        result['details'] = 'Sender is not authorized but owner has not explicitly denied'
    elif headers.spf_result is None:
        result['warning'] = 'No SPF record found'
        result['details'] = 'SPF check was not performed or record is missing'

    return result


def check_dkim(headers: EmailHeaders) -> Dict[str, any]:
    """Analyze DKIM signature result.

    Args:
        headers: Parsed email headers

    Returns:
        Dictionary with DKIM analysis
    """
    result = {
        'status': headers.dkim_result,
        'passed': False,
        'warning': None,
        'details': None
    }

    if headers.dkim_result == 'pass':
        result['passed'] = True
        result['details'] = 'DKIM signature valid'
    elif headers.dkim_result == 'fail':
        result['warning'] = 'DKIM signature invalid - possible tampering'
        result['details'] = 'Email content may have been modified'
    elif headers.dkim_result is None:
        result['warning'] = 'No DKIM signature'
        result['details'] = 'DKIM check was not performed'

    return result


def check_dmarc(headers: EmailHeaders) -> Dict[str, any]:
    """Analyze DMARC policy result.

    Args:
        headers: Parsed email headers

    Returns:
        Dictionary with DMARC analysis
    """
    result = {
        'status': headers.dmarc_result,
        'passed': False,
        'warning': None,
        'details': None
    }

    if headers.dmarc_result == 'pass':
        result['passed'] = True
        result['details'] = 'DMARC policy passed'
    elif headers.dmarc_result == 'fail':
        result['warning'] = 'DMARC policy failed'
        result['details'] = 'Email failed DMARC policy check'
    elif headers.dmarc_result is None:
        result['warning'] = 'No DMARC result'
        result['details'] = 'DMARC check was not performed'

    return result


def analyze_authentication(headers: EmailHeaders) -> Dict[str, Dict[str, any]]:
    """Analyze all authentication methods.

    Args:
        headers: Parsed email headers

    Returns:
        Dictionary with SPF, DKIM, and DMARC analysis
    """
    return {
        'spf': check_spf(headers),
        'dkim': check_dkim(headers),
        'dmarc': check_dmarc(headers),
    }