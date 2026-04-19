"""Output formatters module.

This module provides various output formatters for analysis results,
including JSON, CLI (colorized), and Markdown formats.
"""

import json
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from termcolor import colored
    TERMCOLOR_AVAILABLE = True
except ImportError:
    TERMCOLOR_AVAILABLE = False


@dataclass
class AnalysisOutput:
    """Analysis output container."""

    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    summary: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, Any] = field(default_factory=dict)
    authentication: Dict[str, Any] = field(default_factory=dict)
    urls: List[Dict[str, Any]] = field(default_factory=list)
    domains: List[Dict[str, Any]] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    hashes: List[Dict[str, Any]] = field(default_factory=list)
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class OutputFormatter(ABC):
    """Abstract base class for output formatters."""

    @abstractmethod
    def format(self, output: AnalysisOutput) -> str:
        """Format analysis output.

        Args:
            output: AnalysisOutput object

        Returns:
            Formatted string
        """
        pass


class JSONFormatter(OutputFormatter):
    """JSON output formatter."""

    def __init__(self, indent: int = 2, sort_keys: bool = True):
        """Initialize formatter.

        Args:
            indent: JSON indentation
            sort_keys: Sort dictionary keys
        """
        self.indent = indent
        self.sort_keys = sort_keys

    def format(self, output: AnalysisOutput) -> str:
        """Format as JSON.

        Args:
            output: AnalysisOutput object

        Returns:
            JSON string
        """
        data = {
            'timestamp': output.timestamp,
            'summary': output.summary,
            'headers': output.headers,
            'authentication': output.authentication,
            'urls': output.urls,
            'domains': output.domains,
            'emails': output.emails,
            'hashes': output.hashes,
            'threat_intel': output.threat_intel,
            'errors': output.errors
        }

        return json.dumps(data, indent=self.indent, sort_keys=self.sort_keys)

    def format_compact(self, output: AnalysisOutput) -> str:
        """Format as compact JSON (no indent).

        Args:
            output: AnalysisOutput object

        Returns:
            Compact JSON string
        """
        data = {
            'timestamp': output.timestamp,
            'summary': output.summary,
            'urls': output.urls,
            'domains': output.domains,
            'hashes': output.hashes,
            'threat_intel': output.threat_intel,
            'errors': output.errors
        }

        return json.dumps(data, separators=(',', ':'))


class CLIFormatter(OutputFormatter):
    """CLI output formatter with colors."""

    def __init__(self, use_colors: bool = True, verbose: bool = False):
        """Initialize formatter.

        Args:
            use_colors: Use terminal colors
            verbose: Show detailed output
        """
        self.use_colors = use_colors and TERMCOLOR_AVAILABLE
        self.verbose = verbose

    def _color(self, text: str, color: str) -> str:
        """Apply color to text.

        Args:
            text: Text to color
            color: Color name

        Returns:
            Colored text or original
        """
        if self.use_colors:
            return colored(text, color)
        return text

    def _status_icon(self, is_malicious: bool, is_safe: Optional[bool] = None) -> str:
        """Get status icon.

        Args:
            is_malicious: Is malicious flag
            is_safe: Is safe flag (optional)

        Returns:
            Status icon string
        """
        if is_malicious:
            return self._color("[!]", 'red')
        if is_safe:
            return self._color("[✓]", 'green')
        return self._color("[?]", 'yellow')

    def format(self, output: AnalysisOutput) -> str:
        """Format for CLI.

        Args:
            output: AnalysisOutput object

        Returns:
            CLI formatted string
        """
        lines = []

        lines.append(self._color("=" * 60, 'cyan'))
        lines.append(self._color("  PHISHING EMAIL ANALYZER - RESULTS", 'cyan'))
        lines.append(self._color("=" * 60, 'cyan'))
        lines.append(f"  Timestamp: {output.timestamp}")
        lines.append("")

        if output.summary:
            lines.append(self._color("-" * 40, 'cyan'))
            lines.append(self._color("  SUMMARY", 'cyan'))
            lines.append(self._color("-" * 40, 'cyan'))
            for key, value in output.summary.items():
                icon = ""
                if key in ('urls_malicious', 'domains_malicious', 'hashes_malicious'):
                    if value > 0:
                        icon = self._color(" [!]", 'red')
                    else:
                        icon = self._color(" [OK]", 'green')
                lines.append(f"  {key}: {value}{icon}")
            lines.append("")

        if output.authentication:
            lines.append(self._color("-" * 40, 'cyan'))
            lines.append(self._color("  AUTHENTICATION", 'cyan'))
            lines.append(self._color("-" * 40, 'cyan'))

            for auth_type, auth_data in output.authentication.items():
                status = auth_data.get('passed', False)
                status_icon = self._color("✓", 'green') if status else self._color("✗", 'red')
                status_text = self._color("PASS", 'green') if status else self._color("FAIL", 'red')

                lines.append(f"  {auth_type.upper()}: {status_icon} {status_text}")

                if auth_data.get('warning'):
                    warning_color = 'yellow' if auth_data.get('passed') else 'red'
                    lines.append(f"    {self._color('⚠ ' + auth_data['warning'], warning_color)}")

            lines.append("")

        if output.headers and self.verbose:
            lines.append(self._color("-" * 40, 'cyan'))
            lines.append(self._color("  EMAIL HEADERS", 'cyan'))
            lines.append(self._color("-" * 40, 'cyan'))

            important_headers = ['from_addr', 'reply_to', 'subject', 'date']
            for header in important_headers:
                if header in output.headers and output.headers[header]:
                    lines.append(f"  {header}: {output.headers[header]}")

            lines.append("")

        if output.urls:
            lines.append(self._color("-" * 40, 'cyan'))
            lines.append(self._color(f"  URLS ({len(output.urls)})", 'cyan'))
            lines.append(self._color("-" * 40, 'cyan'))

            for url_data in output.urls:
                malicious = url_data.get('is_malicious', False)
                suspicious = url_data.get('is_suspicious', False)

                if malicious:
                    icon = self._color("[!] ", 'red')
                    color = 'red'
                elif suspicious:
                    icon = self._color("[?] ", 'yellow')
                    color = 'yellow'
                else:
                    icon = self._color("[ ] ", 'green')
                    color = 'white'

                lines.append(f"  {icon}{self._color(url_data.get('url', ''), color)}")

                if self.verbose:
                    if url_data.get('domain'):
                        lines.append(f"      Domain: {url_data['domain']}")
                    if url_data.get('threat_intel'):
                        lines.append(f"      Threat: {url_data['threat_intel']}")

            lines.append("")

        if output.domains:
            lines.append(self._color("-" * 40, 'cyan'))
            lines.append(self._color(f"  DOMAINS ({len(output.domains)})", 'cyan'))
            lines.append(self._color("-" * 40, 'cyan'))

            for domain_data in output.domains:
                malicious = domain_data.get('is_malicious', False)
                suspicious_patterns = domain_data.get('suspicious_patterns', [])

                if malicious:
                    icon = self._color("[!] ", 'red')
                elif suspicious_patterns:
                    icon = self._color("[?] ", 'yellow')
                else:
                    icon = self._color("[ ] ", 'green')

                lines.append(f"  {icon}{domain_data.get('domain', '')}")

                if self.verbose and suspicious_patterns:
                    lines.append(f"      Suspicious: {', '.join(suspicious_patterns)}")

            lines.append("")

        if output.hashes:
            lines.append(self._color("-" * 40, 'cyan'))
            lines.append(self._color(f"  HASHES ({len(output.hashes)})", 'cyan'))
            lines.append(self._color("-" * 40, 'cyan'))

            for hash_data in output.hashes:
                malicious = hash_data.get('is_malicious', False)

                icon = self._color("[!] ", 'red') if malicious else self._color("[ ] ", 'white')
                lines.append(f"  {icon}{hash_data.get('hash_value', '')} ({hash_data.get('hash_type', '').upper()})")

                if self.verbose and hash_data.get('threat_intel'):
                    lines.append(f"      Threat Intel: {hash_data['threat_intel']}")

            lines.append("")

        if output.threat_intel:
            lines.append(self._color("-" * 40, 'cyan'))
            lines.append(self._color("  THREAT INTELLIGENCE", 'cyan'))
            lines.append(self._color("-" * 40, 'cyan'))

            for source, data in output.threat_intel.items():
                if data and data.get('is_malicious'):
                    lines.append(f"  {self._color('[!] ' + source, 'red')} - MALICIOUS")
                else:
                    lines.append(f"  {self._color('[ ] ' + source, 'green')} - Clean")

            lines.append("")

        if output.errors:
            lines.append(self._color("-" * 40, 'red'))
            lines.append(self._color("  ERRORS", 'red'))
            lines.append(self._color("-" * 40, 'red'))
            for error in output.errors:
                lines.append(f"  {self._color('• ' + error, 'red')}")
            lines.append("")

        lines.append(self._color("=" * 60, 'cyan'))

        return "\n".join(lines)

    def format_compact(self, output: AnalysisOutput) -> str:
        """Format compact summary for CLI.

        Args:
            output: AnalysisOutput object

        Returns:
            Compact CLI output
        """
        lines = []

        summary = output.summary
        threat_level = summary.get('threat_level', 'unknown')

        if threat_level == 'high':
            level = self._color("HIGH", 'red')
        elif threat_level == 'medium':
            level = self._color("MEDIUM", 'yellow')
        else:
            level = self._color("LOW", 'green')

        lines.append(f"Threat Level: {level}")
        lines.append(f"URLs: {summary.get('urls_total', 0)} | Malicious: {summary.get('urls_malicious', 0)}")
        lines.append(f"Domains: {summary.get('domains_total', 0)} | Malicious: {summary.get('domains_malicious', 0)}")
        lines.append(f"Hashes: {summary.get('hashes_total', 0)} | Malicious: {summary.get('hashes_malicious', 0)}")

        return "\n".join(lines)


class MarkdownFormatter(OutputFormatter):
    """Markdown output formatter."""

    def __init__(self, include_toc: bool = True):
        """Initialize formatter.

        Args:
            include_toc: Include table of contents
        """
        self.include_toc = include_toc

    def format(self, output: AnalysisOutput) -> str:
        """Format as Markdown.

        Args:
            output: AnalysisOutput object

        Returns:
            Markdown formatted string
        """
        lines = []

        lines.append("# Phishing Email Analysis Report")
        lines.append("")
        lines.append(f"**Date:** {output.timestamp}")
        lines.append("")

        if self.include_toc:
            lines.append("## Table of Contents")
            lines.append("")
            lines.append("1. [Summary](#summary)")
            lines.append("2. [Authentication](#authentication)")
            lines.append("3. [URLs](#urls)")
            lines.append("4. [Domains](#domains)")
            lines.append("5. [Hashes](#hashes)")
            lines.append("6. [Threat Intelligence](#threat-intelligence)")
            lines.append("")

        if output.summary:
            lines.append("## Summary")
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")

            for key, value in output.summary.items():
                lines.append(f"| {key} | {value} |")

            lines.append("")

        if output.authentication:
            lines.append("## Authentication")
            lines.append("")

            for auth_type, auth_data in output.authentication.items():
                passed = auth_data.get('passed', False)
                status = "✅ PASS" if passed else "❌ FAIL"

                lines.append(f"### {auth_type.upper()}")
                lines.append("")
                lines.append(f"**Status:** {status}")
                lines.append("")

                if auth_data.get('details'):
                    lines.append(f"**Details:** {auth_data['details']}")
                    lines.append("")

                if auth_data.get('warning'):
                    lines.append(f"**Warning:** {auth_data['warning']}")
                    lines.append("")

        if output.urls:
            lines.append("## URLs")
            lines.append("")

            lines.append("| URL | Domain | Malicious | Threat Intel |")
            lines.append("|-----|--------|-----------|-------------|")

            for url_data in output.urls:
                malicious = "❌" if url_data.get('is_malicious') else "✅"
                threat = url_data.get('threat_intel', '-')
                lines.append(f"| {url_data.get('url', '')} | {url_data.get('domain', '')} | {malicious} | {threat} |")

            lines.append("")

        if output.domains:
            lines.append("## Domains")
            lines.append("")

            lines.append("| Domain | TLD | Malicious | Suspicious Patterns |")
            lines.append("|--------|-----|-----------|---------------------|")

            for domain_data in output.domains:
                malicious = "❌" if domain_data.get('is_malicious') else "✅"
                patterns = ", ".join(domain_data.get('suspicious_patterns', [])) or "-"
                lines.append(f"| {domain_data.get('domain', '')} | {domain_data.get('tld', '')} | {malicious} | {patterns} |")

            lines.append("")

        if output.hashes:
            lines.append("## Hashes")
            lines.append("")

            lines.append("| Hash | Type | Malicious |")
            lines.append("|------|------|-----------|")

            for hash_data in output.hashes:
                malicious = "❌" if hash_data.get('is_malicious') else "✅"
                lines.append(f"| {hash_data.get('hash_value', '')} | {hash_data.get('hash_type', '').upper()} | {malicious} |")

            lines.append("")

        if output.threat_intel:
            lines.append("## Threat Intelligence")
            lines.append("")

            for source, data in output.threat_intel.items():
                lines.append(f"### {source}")
                lines.append("")

                if data and data.get('is_malicious'):
                    lines.append("**Status:** ❌ MALICIOUS")
                    lines.append("")
                else:
                    lines.append("**Status:** ✅ Clean")
                    lines.append("")

        if output.errors:
            lines.append("## Errors")
            lines.append("")

            for error in output.errors:
                lines.append(f"- {error}")

            lines.append("")

        return "\n".join(lines)


def create_formatter(format_type: str, **kwargs) -> OutputFormatter:
    """Create formatter by type.

    Args:
        format_type: Formatter type ('json', 'cli', 'markdown', 'csv', 'html')
        **kwargs: Formatter arguments

    Returns:
        OutputFormatter instance
    """
    formatters = {
        'json': JSONFormatter,
        'cli': CLIFormatter,
        'markdown': MarkdownFormatter,
        'csv': CSVFormatter,
        'html': HTMLReportFormatter,
    }

    formatter_class = formatters.get(format_type.lower())
    if not formatter_class:
        raise ValueError(f"Unknown formatter type: {format_type}")

    return formatter_class(**kwargs)


class CSVFormatter(OutputFormatter):
    """CSV output formatter for spreadsheet analysis."""

    def __init__(self, delimiter: str = ',', include_all_fields: bool = False):
        """Initialize formatter.

        Args:
            delimiter: CSV delimiter (comma, semicolon, tab)
            include_all_fields: Include all available fields
        """
        self.delimiter = delimiter
        self.include_all_fields = include_all_fields

    def format(self, output: AnalysisOutput) -> str:
        """Format as CSV.

        Args:
            output: AnalysisOutput object

        Returns:
            CSV string
        """
        rows = []

        summary = output.summary
        auth = output.authentication

        rows.append(["PHISHING EMAIL ANALYSIS REPORT"])
        rows.append([f"Timestamp{self.delimiter}{output.timestamp}"])
        rows.append([f"Threat Level{self.delimiter}{summary.get('threat_level', 'unknown')}"])
        rows.append([f"Threat Score{self.delimiter}{summary.get('threat_score', 0)}"])
        rows.append([])

        rows.append(["AUTHENTICATION"])
        rows.append([f"SPF{self.delimiter}{auth.get('spf', {}).get('status', 'N/A')}{self.delimiter}Passed: {auth.get('spf', {}).get('passed', False)}"])
        rows.append([f"DKIM{self.delimiter}{auth.get('dkim', {}).get('status', 'N/A')}{self.delimiter}Passed: {auth.get('dkim', {}).get('passed', False)}"])
        rows.append([f"DMARC{self.delimiter}{auth.get('dmarc', {}).get('status', 'N/A')}{self.delimiter}Passed: {auth.get('dmarc', {}).get('passed', False)}"])
        rows.append([])

        if output.urls:
            rows.append(["URLS"])
            header = ["URL", "Domain", "Scheme", "Malicious", "Suspicious", "Shortened", "Threat Intel"]
            rows.append(self.delimiter.join(header))

            for url in output.urls:
                row = [
                    url.get('url', ''),
                    url.get('domain', ''),
                    url.get('scheme', ''),
                    str(url.get('is_malicious', False)),
                    str(url.get('is_suspicious', False)),
                    str(url.get('is_shortened', False)),
                    str(url.get('threat_intel', ''))
                ]
                rows.append(self.delimiter.join(row))
            rows.append([])

        if output.domains:
            rows.append(["DOMAINS"])
            header = ["Domain", "TLD", "SLD", "Malicious", "Suspicious Patterns", "Has Numbers", "Is IP"]
            rows.append(self.delimiter.join(header))

            for domain in output.domains:
                row = [
                    domain.get('domain', ''),
                    domain.get('tld', ''),
                    domain.get('sld', ''),
                    str(domain.get('is_malicious', False)),
                    '|'.join(domain.get('suspicious_patterns', [])),
                    str(domain.get('has_numbers', False)),
                    str(domain.get('is_ip', False))
                ]
                rows.append(self.delimiter.join(row))
            rows.append([])

        if output.hashes:
            rows.append(["HASHES"])
            header = ["Hash Value", "Hash Type", "Length", "Malicious", "Threat Intel"]
            rows.append(self.delimiter.join(header))

            for h in output.hashes:
                row = [
                    h.get('hash_value', ''),
                    h.get('hash_type', ''),
                    str(h.get('length', 0)),
                    str(h.get('is_malicious', False)),
                    str(h.get('threat_intel', ''))
                ]
                rows.append(self.delimiter.join(row))
            rows.append([])

        if output.emails:
            rows.append(["EMAIL ADDRESSES"])
            for email in output.emails:
                rows.append([f"Email{self.delimiter}{email}"])
            rows.append([])

        if output.headers:
            rows.append(["EMAIL HEADERS"])
            for key, value in output.headers.items():
                if value:
                    rows.append([f"{key}{self.delimiter}{value}"])
            rows.append([])

        if output.errors:
            rows.append(["ERRORS"])
            for error in output.errors:
                rows.append([f"Error{self.delimiter}{error}"])

        csv_lines = []
        for row in rows:
            if isinstance(row, list):
                csv_lines.append(self.delimiter.join(row))
            else:
                csv_lines.append(str(row))

        return '\n'.join(csv_lines)

    def format_compact(self, output: AnalysisOutput) -> str:
        """Format compact CSV summary.

        Args:
            output: AnalysisOutput object

        Returns:
            Compact CSV string
        """
        summary = output.summary
        auth = output.authentication

        header = ["URL", "Domain", "Hash", "Threat Level", "SPF", "DKIM", "DMARC"]

        url = output.urls[0].get('url', '') if output.urls else ''
        domain = output.domains[0].get('domain', '') if output.domains else ''
        hash_val = output.hashes[0].get('hash_value', '')[:16] if output.hashes else ''

        row = [
            url[:50],
            domain[:30],
            hash_val,
            summary.get('threat_level', 'unknown'),
            auth.get('spf', {}).get('status', 'N/A'),
            auth.get('dkim', {}).get('status', 'N/A'),
            auth.get('dmarc', {}).get('status', 'N/A'),
        ]

        return self.delimiter.join(header) + '\n' + self.delimiter.join(row)


class HTMLReportFormatter(OutputFormatter):
    """HTML report formatter with styling."""

    def __init__(self, title: str = "Phishing Email Analysis Report", include_css: bool = True):
        """Initialize formatter.

        Args:
            title: Report title
            include_css: Include inline CSS styles
        """
        self.title = title
        self.include_css = include_css

    def format(self, output: AnalysisOutput) -> str:
        """Format as HTML report.

        Args:
            output: AnalysisOutput object

        Returns:
            HTML string
        """
        summary = output.summary
        auth = output.authentication
        threat_level = summary.get('threat_level', 'unknown')

        threat_colors = {'high': '#dc3545', 'medium': '#ffc107', 'low': '#28a745'}
        threat_color = threat_colors.get(threat_level, '#6c757d')

        html = ['<!DOCTYPE html>']
        html.append('<html lang="en">')
        html.append('<head>')
        html.append(f'<meta charset="UTF-8">')
        html.append(f'<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html.append(f'<title>{self.title}</title>')

        if self.include_css:
            html.append('<style>')
            html.append('body { font-family: "Segoe UI", Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }')
            html.append('.container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }')
            html.append('h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }')
            html.append('h2 { color: #555; margin-top: 30px; border-left: 4px solid #007bff; padding-left: 10px; }')
            html.append('.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }')
            html.append('.summary-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }')
            html.append('.summary-card .value { font-size: 2em; font-weight: bold; color: #007bff; }')
            html.append('.summary-card .label { color: #666; margin-top: 5px; }')
            html.append('.threat-badge { display: inline-block; padding: 10px 20px; border-radius: 5px; color: white; font-weight: bold; font-size: 1.2em; }')
            html.append('table { width: 100%; border-collapse: collapse; margin: 15px 0; }')
            html.append('th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }')
            html.append('th { background: #007bff; color: white; }')
            html.append('tr:hover { background: #f8f9fa; }')
            html.append('.malicious { color: #dc3545; font-weight: bold; }')
            html.append('.safe { color: #28a745; }')
            html.append('.warning { color: #ffc107; }')
            html.append('.auth-pass { color: #28a745; }')
            html.append('.auth-fail { color: #dc3545; }')
            html.append('.timestamp { color: #999; font-size: 0.9em; }')
            html.append('.footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #999; text-align: center; }')
            html.append('.suspicious-tag { background: #ffc107; color: #333; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }')
            html.append('.malicious-tag { background: #dc3545; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }')
            html.append('</style>')

        html.append('</head>')
        html.append('<body>')
        html.append('<div class="container">')

        html.append(f'<h1>🎣 {self.title}</h1>')
        html.append(f'<p class="timestamp">Generated: {output.timestamp}</p>')

        html.append(f'<div style="text-align: center; margin: 30px 0;">')
        html.append(f'<span class="threat-badge" style="background: {threat_color};">THREAT LEVEL: {threat_level.upper()}</span>')
        html.append(f'<p>Threat Score: {summary.get("threat_score", 0)}/9</p>')
        html.append('</div>')

        html.append('<h2>📊 Summary</h2>')
        html.append('<div class="summary-grid">')
        html.append(f'<div class="summary-card"><div class="value">{len(output.urls)}</div><div class="label">URLs Found</div></div>')
        html.append(f'<div class="summary-card"><div class="value">{summary.get("urls_malicious", 0)}</div><div class="label">Malicious URLs</div></div>')
        html.append(f'<div class="summary-card"><div class="value">{len(output.domains)}</div><div class="label">Domains Found</div></div>')
        html.append(f'<div class="summary-card"><div class="value">{len(output.hashes)}</div><div class="label">Hashes Found</div></div>')
        html.append('</div>')

        html.append('<h2>🔐 Authentication</h2>')
        html.append('<table>')
        html.append('<tr><th>Check</th><th>Status</th><th>Details</th></tr>')

        for auth_name, auth_data in [('SPF', auth.get('spf', {})), ('DKIM', auth.get('dkim', {})), ('DMARC', auth.get('dmarc', {}))]:
            passed = auth_data.get('passed', False)
            status_class = 'auth-pass' if passed else 'auth-fail'
            status_icon = '✓' if passed else '✗'
            status = f'<span class="{status_class}">{status_icon} {"PASS" if passed else "FAIL"}</span>'
            details = auth_data.get('details', '')

            html.append(f'<tr><td><strong>{auth_name}</strong></td><td>{status}</td><td>{details}</td></tr>')

        html.append('</table>')

        if output.urls:
            html.append('<h2>🔗 URLs</h2>')
            html.append('<table>')
            html.append('<tr><th>URL</th><th>Domain</th><th>Status</th></tr>')

            for url in output.urls:
                is_mal = url.get('is_malicious', False)
                is_susp = url.get('is_suspicious', False)
                status = '❌ Malicious' if is_mal else ('⚠️ Suspicious' if is_susp else '✅ Safe')
                status_class = 'malicious' if is_mal else ('warning' if is_susp else 'safe')

                html.append(f'<tr><td>{url.get("url", "")[:60]}...</td><td>{url.get("domain", "")}</td><td class="{status_class}">{status}</td></tr>')

            html.append('</table>')

        if output.domains:
            html.append('<h2>🌐 Domains</h2>')
            html.append('<table>')
            html.append('<tr><th>Domain</th><th>TLD</th><th>Suspicious Patterns</th><th>Status</th></tr>')

            for domain in output.domains:
                is_mal = domain.get('is_malicious', False)
                patterns = domain.get('suspicious_patterns', [])
                pattern_tags = ''.join([f'<span class="suspicious-tag">{p}</span> ' for p in patterns])
                status = '❌ Malicious' if is_mal else ('⚠️ Suspicious' if patterns else '✅ Safe')
                status_class = 'malicious' if is_mal else ('warning' if patterns else 'safe')

                html.append(f'<tr><td>{domain.get("domain", "")}</td><td>{domain.get("tld", "")}</td><td>{pattern_tags}</td><td class="{status_class}">{status}</td></tr>')

            html.append('</table>')

        if output.hashes:
            html.append('<h2>🔐 Hashes</h2>')
            html.append('<table>')
            html.append('<tr><th>Hash</th><th>Type</th><th>Length</th><th>Status</th></tr>')

            for h in output.hashes:
                is_mal = h.get('is_malicious', False)
                status = '❌ Malicious' if is_mal else '✅ Safe'
                status_class = 'malicious' if is_mal else 'safe'

                html.append(f'<tr><td><code>{h.get("hash_value", "")}</code></td><td>{h.get("hash_type", "").upper()}</td><td>{h.get("length", 0)}</td><td class="{status_class}">{status}</td></tr>')

            html.append('</table>')

        if output.headers:
            html.append('<h2>📧 Email Headers</h2>')
            html.append('<table>')
            html.append('<tr><th>Header</th><th>Value</th></tr>')

            for key, value in output.headers.items():
                if value:
                    html.append(f'<tr><td><strong>{key}</strong></td><td>{value}</td></tr>')

            html.append('</table>')

        if output.errors:
            html.append('<h2>❌ Errors</h2>')
            html.append('<ul>')
            for error in output.errors:
                html.append(f'<li class="malicious">{error}</li>')
            html.append('</ul>')

        html.append('<div class="footer">')
        html.append('<p>Phishing Email Analyzer - Generated Report</p>')
        html.append('</div>')

        html.append('</div>')
        html.append('</body>')
        html.append('</html>')

        return '\n'.join(html)

    def format_compact(self, output: AnalysisOutput) -> str:
        """Format compact HTML summary.

        Args:
            output: AnalysisOutput object

        Returns:
            Compact HTML string
        """
        return self.format(output)