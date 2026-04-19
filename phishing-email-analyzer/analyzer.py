"""Phishing Email Analyzer core module.

This module provides the core analysis functionality, integrating extraction
and enrichment modules for comprehensive email analysis.
"""

import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from extractors.headers import (
    extract_headers,
    EmailHeaders,
    analyze_authentication,
)
from extractors.urls import (
    extract_urls,
    extract_domains,
    extract_emails,
    analyze_domain,
)
from extractors.hashes import (
    extract_hashes,
    ExtractedHash,
)
from extractors.html_analyzer import (
    analyze_html_content,
    extract_attachments_from_email,
    check_reply_to_mismatch,
    check_sender_domain_quality,
)
from enrichers.abusech import AbuseChEnricher
from enrichers.otx import AlienVaultOTX
from enrichers.virustotal import VirusTotalEnricher
from output.formatters import AnalysisOutput


@dataclass
class AnalysisConfig:
    """Configuration for email analysis."""

    virustotal_api_key: Optional[str] = None
    alienvault_api_key: Optional[str] = None
    enrich_domains: bool = True
    enrich_urls: bool = True
    enrich_hashes: bool = True
    enrich_ips: bool = True
    timeout: int = 30
    verbose: bool = False


@dataclass
class AnalysisResult:
    """Analysis result container."""

    headers: EmailHeaders = field(default_factory=EmailHeaders)
    urls: List[Dict[str, Any]] = field(default_factory=list)
    domains: List[Dict[str, Any]] = field(default_factory=list)
    hashes: List[Dict[str, Any]] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    authentication: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    text_iocs: Dict[str, Any] = field(default_factory=dict)
    html_analysis: Dict[str, Any] = field(default_factory=dict)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    sender_analysis: Dict[str, Any] = field(default_factory=dict)


class PhishingEmailAnalyzer:
    """Phishing Email Analyzer.

    Analyzes email content for phishing indicators and enriches with threat intelligence.

    Example:
        >>> config = AnalysisConfig()
        >>> analyzer = PhishingEmailAnalyzer(config)
        >>> result = analyzer.analyze_email(email_content)
        >>> print(result.summary['threat_level'])
        high
    """

    def __init__(self, config: Optional[AnalysisConfig] = None):
        """Initialize analyzer.

        Args:
            config: Analysis configuration (uses defaults if None)
        """
        self.config = config or AnalysisConfig()
        self.abusech = None
        self.otx = None
        self.virustotal = None

        self._init_enrichers()

    def _init_enrichers(self) -> None:
        """Initialize threat intelligence enrichers."""
        self.abusech = AbuseChEnricher(timeout=self.config.timeout)

        if self.config.alienvault_api_key:
            self.otx = AlienVaultOTX(
                api_key=self.config.alienvault_api_key,
                timeout=self.config.timeout
            )

        if self.config.virustotal_api_key:
            self.virustotal = VirusTotalEnricher(
                api_key=self.config.virustotal_api_key,
                timeout=self.config.timeout
            )

    def analyze_email(self, email_content: str) -> AnalysisResult:
        """Analyze email content.

        Args:
            email_content: Raw email content (headers + body)

        Returns:
            AnalysisResult with all findings

        Example:
            >>> result = analyzer.analyze_email(raw_email)
            >>> print(f"Found {len(result.urls)} URLs")
            Found 5 URLs
        """
        result = AnalysisResult()

        try:
            result.headers = extract_headers(email_content)
        except Exception as e:
            result.errors.append(f"Header extraction error: {str(e)}")

        try:
            result.authentication = self._analyze_authentication(result.headers)
        except Exception as e:
            result.errors.append(f"Authentication analysis error: {str(e)}")

        try:
            extracted_urls = extract_urls(email_content)
            result.urls = self._process_urls(extracted_urls)
        except Exception as e:
            result.errors.append(f"URL extraction error: {str(e)}")

        try:
            extracted_domains = extract_domains(email_content)
            result.domains = self._process_domains(extracted_domains)
        except Exception as e:
            result.errors.append(f"Domain extraction error: {str(e)}")

        try:
            extracted_iocs = self._extract_text_iocs(email_content)
            result.text_iocs = extracted_iocs
        except Exception as e:
            result.errors.append(f"Text IoC extraction error: {str(e)}")

        try:
            result.emails = extract_emails(email_content)
        except Exception as e:
            result.errors.append(f"Email extraction error: {str(e)}")

        try:
            extracted_hashes = extract_hashes(email_content)
            result.hashes = self._process_hashes(extracted_hashes)
        except Exception as e:
            result.errors.append(f"Hash extraction error: {str(e)}")

        try:
            html_analysis = analyze_html_content(email_content)
            result.html_analysis = {
                'has_html': html_analysis.has_html,
                'risk_score': html_analysis.risk_score,
                'suspicious_scripts': html_analysis.suspicious_scripts,
                'iframes': html_analysis.iframes,
                'obfuscated_links': html_analysis.obfuscated_links,
                'forms': html_analysis.forms,
                'suspicious_events': html_analysis.suspicious_events,
            }
        except Exception as e:
            result.errors.append(f"HTML analysis error: {str(e)}")

        try:
            attachments = extract_attachments_from_email(email_content)
            result.attachments = attachments
        except Exception as e:
            result.errors.append(f"Attachment extraction error: {str(e)}")

        try:
            headers_dict = {
                'from': result.headers.from_addr,
                'reply_to': result.headers.reply_to,
            }
            reply_to_check = check_reply_to_mismatch(headers_dict)

            sender_analysis = {
                'reply_to_mismatch': reply_to_check.get('mismatch', False),
                'from_email': reply_to_check.get('from_email', ''),
                'reply_to_email': reply_to_check.get('reply_to_email', ''),
            }

            if result.headers.from_addr:
                sender_domain = check_sender_domain_quality(result.headers.from_addr)
                sender_analysis['domain_quality'] = sender_domain

            result.sender_analysis = sender_analysis
        except Exception as e:
            result.errors.append(f"Sender analysis error: {str(e)}")

        try:
            result.threat_intel = self._enrich_threat_intel(result)
        except Exception as e:
            result.errors.append(f"Threat intel enrichment error: {str(e)}")

        try:
            result.summary = self._create_summary(result)
        except Exception as e:
            result.errors.append(f"Summary creation error: {str(e)}")

        return result

    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze email from file.

        Args:
            file_path: Path to .eml or .msg file

        Returns:
            AnalysisResult with findings
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except IOError as e:
            result = AnalysisResult()
            result.errors.append(f"File read error: {str(e)}")
            return result

        return self.analyze_email(content)

    def _extract_text_iocs(self, text: str) -> Dict[str, Any]:
        """Extract IoCs from plain text in email body.

        Args:
            text: Email text content

        Returns:
            Dictionary with extracted IoCs
        """
        iocs = {
            'bitcoin_addresses': [],
            'ethereum_addresses': [],
            'iban_accounts': [],
            'phone_numbers': [],
            'potential_domains': [],
            'urgency_keywords': [],
            'financial_keywords': [],
            'suspicious_keywords': [],
        }

        bitcoin_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        iocs['bitcoin_addresses'] = re.findall(bitcoin_pattern, text)

        ethereum_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        iocs['ethereum_addresses'] = re.findall(ethereum_pattern, text)

        iban_pattern = r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b'
        for match in re.finditer(iban_pattern, text):
            iban = match.group(0)
            if len(iban) >= 15 and len(iban) <= 34:
                iocs['iban_accounts'].append(iban)

        phone_pattern = r'(?:\+?351)?\s*[0-9]{3}[.\s-]?[0-9]{3}[.\s-]?[0-9]{3,4}'
        iocs['phone_numbers'] = re.findall(phone_pattern, text)

        potential_domain_pattern = r'(?:bank|transfer|wire|payment|account|secure|login|verify|support)\.[a-z]{2,}'
        iocs['potential_domains'] = re.findall(potential_domain_pattern, text, re.IGNORECASE)

        urgency_keywords = [
            'urgent', 'urgente', 'immediately', 'imediato', 'within 24 hours',
            'nas próximas 24 horas', 'act now', 'age agora', 'suspended',
            'suspendido', 'permanently', 'permanente', 'lock', 'bloqueado',
            'expire', 'expirar', 'deadline', 'prazo', 'limited time',
            'tempo limitado', 'final warning', 'último aviso'
        ]
        found_urgency = []
        text_lower = text.lower()
        for kw in urgency_keywords:
            if kw in text_lower:
                found_urgency.append(kw)
        iocs['urgency_keywords'] = found_urgency

        financial_keywords = [
            'wire transfer', 'transferência', 'bank account', 'conta bancária',
            'iban', 'routing number', 'swift code', 'bic', 'bitcoin', 'btc',
            'ethereum', 'payment', 'pagamento', 'invoice', 'fatura',
            'overdue', 'atrasado', '€', 'eur', 'dollar', 'dólar',
            'credit card', 'cartão de crédito', 'cvv', 'expiry'
        ]
        found_financial = []
        for kw in financial_keywords:
            if kw in text_lower:
                found_financial.append(kw)
        iocs['financial_keywords'] = found_financial

        suspicious_phishing_keywords = [
            'verify your identity', 'verificar sua identidade',
            'confirm your account', 'confirmar sua conta',
            'update your payment', 'atualizar pagamento',
            'click here', 'clique aqui', 'click below', 'clique abaixo',
            'login to', 'entrar em', 'sign in', 'iniciar sessão',
            'unauthorized transaction', 'transação não autorizada',
            'compromised', 'comprometido', 'suspicious activity',
            'atividade suspeita', 'reset password', 'redefinir senha'
        ]
        found_suspicious = []
        for kw in suspicious_phishing_keywords:
            if kw in text_lower:
                found_suspicious.append(kw)
        iocs['suspicious_keywords'] = found_suspicious

        return iocs

    def _analyze_authentication(self, headers: EmailHeaders) -> Dict[str, Dict[str, Any]]:
        """Analyze email authentication.

        Args:
            headers: Parsed email headers

        Returns:
            Dictionary with SPF, DKIM, DMARC analysis
        """
        return analyze_authentication(headers)

    def _process_urls(self, urls: List) -> List[Dict[str, Any]]:
        """Process extracted URLs.

        Args:
            urls: List of ExtractedURL objects

        Returns:
            List of processed URL dictionaries
        """
        processed = []

        for url in urls:
            url_dict = {
                'url': url.url,
                'domain': url.domain,
                'scheme': url.scheme,
                'path': url.path,
                'query': url.query,
                'is_shortened': url.is_shortened,
                'is_suspicious': url.is_suspicious,
                'is_malicious': False,
                'threat_intel': None,
            }

            if self.config.enrich_urls and self.abusech:
                try:
                    abuse_result = self.abusech.check_url(url.url)
                    if abuse_result:
                        url_dict['is_malicious'] = True
                        url_dict['threat_intel'] = {
                            'source': 'urlhaus',
                            'threat': abuse_result.threat,
                            'status': abuse_result.url_status,
                        }
                except Exception:
                    pass

            if url_dict['is_malicious']:
                url_dict['threat_intel_source'] = 'urlhaus'

            processed.append(url_dict)

        return processed

    def _process_domains(self, domains: List) -> List[Dict[str, Any]]:
        """Process extracted domains.

        Args:
            domains: List of ExtractedDomain objects

        Returns:
            List of processed domain dictionaries
        """
        processed = []

        for domain in domains:
            domain_dict = {
                'domain': domain.domain,
                'tld': domain.tld,
                'sld': domain.sld,
                'subdomain': domain.subdomain,
                'is_public': domain.is_public,
                'has_numbers': domain.has_numbers,
                'is_ip': domain.is_ip,
                'suspicious_patterns': domain.suspicious_patterns,
                'is_malicious': False,
                'is_suspicious': bool(domain.suspicious_patterns),
                'threat_intel': None,
            }

            if self.config.enrich_domains and not domain.is_ip:
                if self.abusech:
                    try:
                        abuse_results = self.abusech.check_domain(domain.domain)
                        if abuse_results:
                            domain_dict['is_malicious'] = True
                            domain_dict['threat_intel'] = {
                                'source': 'urlhaus',
                                'count': len(abuse_results),
                            }
                    except Exception:
                        pass

                if self.otx and not domain_dict['is_malicious']:
                    try:
                        otx_result = self.otx.check_domain(domain.domain)
                        if otx_result and otx_result.is_malicious:
                            domain_dict['is_malicious'] = True
                            domain_dict['threat_intel'] = {
                                'source': 'otx',
                                'pulse_count': otx_result.pulse_count,
                            }
                    except Exception:
                        pass

            processed.append(domain_dict)

        return processed

    def _process_hashes(self, hashes: List[ExtractedHash]) -> List[Dict[str, Any]]:
        """Process extracted hashes.

        Args:
            hashes: List of ExtractedHash objects

        Returns:
            List of processed hash dictionaries
        """
        processed = []

        for hash_obj in hashes:
            hash_dict = {
                'hash_value': hash_obj.hash_value,
                'hash_type': hash_obj.hash_type,
                'length': hash_obj.length,
                'is_valid': hash_obj.is_valid,
                'is_malicious': False,
                'threat_intel': None,
            }

            if self.config.enrich_hashes:
                if self.abusech and hash_obj.hash_type == 'sha256':
                    try:
                        mb_result = self.abusech.check_hash(hash_obj.hash_value)
                        if mb_result and mb_result.is_malware:
                            hash_dict['is_malicious'] = True
                            hash_dict['threat_intel'] = {
                                'source': 'malwarebazaar',
                                'malware_names': mb_result.malware_names,
                            }
                    except Exception:
                        pass

                if self.virustotal and not hash_dict['is_malicious']:
                    try:
                        vt_result = self.virustotal.check_hash(hash_obj.hash_value)
                        if vt_result and vt_result.is_malicious:
                            hash_dict['is_malicious'] = True
                            hash_dict['threat_intel'] = {
                                'source': 'virustotal',
                                'malicious_count': vt_result.last_analysis_stats.get('malicious', 0),
                            }
                    except Exception:
                        pass

            processed.append(hash_dict)

        return processed

    def _enrich_threat_intel(self, result: AnalysisResult) -> Dict[str, Any]:
        """Enrich with threat intelligence.

        Args:
            result: Current analysis result

        Returns:
            Dictionary with threat intel results
        """
        threat_intel = {}

        if self.virustotal:
            try:
                for url_data in result.urls[:5]:
                    domain = url_data.get('domain')
                    if domain and not url_data.get('is_malicious'):
                        vt_result = self.virustotal.check_domain(domain)
                        threat_intel[f'vt_domain_{domain}'] = {
                            'is_malicious': vt_result.is_malicious if vt_result else False,
                            'indicator_type': 'domain',
                        }
            except Exception:
                pass

        return threat_intel

    def _create_summary(self, result: AnalysisResult) -> Dict[str, Any]:
        """Create analysis summary.

        Args:
            result: Analysis result

        Returns:
            Summary dictionary
        """
        summary = {
            'timestamp': datetime.now().isoformat(),
            'urls_total': len(result.urls),
            'urls_malicious': sum(1 for u in result.urls if u.get('is_malicious')),
            'urls_suspicious': sum(1 for u in result.urls if u.get('is_suspicious')),
            'domains_total': len(result.domains),
            'domains_malicious': sum(1 for d in result.domains if d.get('is_malicious')),
            'domains_suspicious': sum(1 for d in result.domains if d.get('is_suspicious')),
            'hashes_total': len(result.hashes),
            'hashes_malicious': sum(1 for h in result.hashes if h.get('is_malicious')),
            'emails_found': len(result.emails),
            'attachments_found': len(result.attachments),
            'attachments_suspicious': sum(1 for a in result.attachments if a.get('suspicious')),
            'html_risk_score': result.html_analysis.get('risk_score', 0) if result.html_analysis else 0,
            'reply_to_mismatch': result.sender_analysis.get('reply_to_mismatch', False) if result.sender_analysis else False,
            'sender_domain_suspicious': result.sender_analysis.get('domain_quality', {}).get('suspicious', False) if result.sender_analysis else False,
        }

        auth = result.authentication
        summary['spf_passed'] = auth.get('spf', {}).get('passed', False)
        summary['dkim_passed'] = auth.get('dkim', {}).get('passed', False)
        summary['dmarc_passed'] = auth.get('dmarc', {}).get('passed', False)

        threat_level = 'low'
        score = 0

        if summary['urls_malicious'] > 0:
            score += 3
        if summary['domains_malicious'] > 0:
            score += 3
        if summary['hashes_malicious'] > 0:
            score += 3

        if not summary['spf_passed'] or not summary['dkim_passed']:
            score += 2

        if summary['domains_suspicious'] > 0:
            score += summary['domains_suspicious']

        if summary['urls_suspicious'] > 0:
            score += summary['urls_suspicious']

        if summary['urls_total'] > 0 and not summary['urls_suspicious'] and not summary['urls_malicious']:
            has_suspicious_domain = any(d.get('is_suspicious') for d in result.domains)
            if has_suspicious_domain:
                score += 1

        text_iocs = getattr(result, 'text_iocs', {})
        if text_iocs:
            if text_iocs.get('bitcoin_addresses'):
                score += 3
            if text_iocs.get('ethereum_addresses'):
                score += 3
            if text_iocs.get('iban_accounts'):
                score += 3
            if text_iocs.get('phone_numbers'):
                score += 1
            if text_iocs.get('urgency_keywords'):
                score += len(text_iocs['urgency_keywords'])
            if text_iocs.get('financial_keywords'):
                score += min(len(text_iocs['financial_keywords']), 2)
            if text_iocs.get('suspicious_keywords'):
                score += min(len(text_iocs['suspicious_keywords']), 2)

        html_analysis = getattr(result, 'html_analysis', {})
        if html_analysis:
            score += html_analysis.get('risk_score', 0) // 2

        attachments = getattr(result, 'attachments', [])
        for att in attachments:
            score += att.get('risk_score', 0)

        sender_analysis = getattr(result, 'sender_analysis', {})
        if sender_analysis.get('reply_to_mismatch'):
            score += 3

        domain_quality = sender_analysis.get('domain_quality', {})
        if domain_quality:
            score += domain_quality.get('risk_score', 0)

        if score >= 6:
            threat_level = 'high'
        elif score >= 3:
            threat_level = 'medium'
        else:
            threat_level = 'low'

        summary['threat_level'] = threat_level
        summary['threat_score'] = score

        return summary

    def get_output(self, result: AnalysisResult) -> AnalysisOutput:
        """Convert result to output format.

        Args:
            result: AnalysisResult

        Returns:
            AnalysisOutput for formatters
        """
        return AnalysisOutput(
            timestamp=result.summary.get('timestamp', datetime.now().isoformat()),
            summary=result.summary,
            headers={
                'from': result.headers.from_addr,
                'reply_to': result.headers.reply_to,
                'subject': result.headers.subject,
                'date': result.headers.date,
                'return_path': result.headers.return_path,
            },
            authentication=result.authentication,
            urls=result.urls,
            domains=result.domains,
            emails=result.emails,
            hashes=result.hashes,
            threat_intel=result.threat_intel,
            errors=result.errors
        )

    def close(self) -> None:
        """Close all enricher sessions."""
        if self.abusech:
            self.abusech.close()
        if self.otx:
            self.otx.close()
        if self.virustotal:
            self.virustotal.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()