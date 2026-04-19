#!/usr/bin/env python3
"""Phishing Email Analyzer - CLI Entry Point.

A command-line tool for analyzing phishing emails, extracting IoCs,
and enriching with threat intelligence.
"""

import argparse
import sys
import os
import io
from pathlib import Path

from analyzer import PhishingEmailAnalyzer, AnalysisConfig
from output.formatters import (
    create_formatter,
    AnalysisOutput,
    JSONFormatter,
    CLIFormatter,
    MarkdownFormatter,
    CSVFormatter,
    HTMLReportFormatter,
)
from extractors.msg_parser import is_msg_file, extract_msg_as_text


def read_email_from_file(file_path: str) -> str:
    """Read email content from file.

    Args:
        file_path: Path to email file

    Returns:
        Email content as string
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if is_msg_file(file_path):
        print(f"Detected .msg file, extracting content...")
        return extract_msg_as_text(file_path)

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except IOError as e:
        raise IOError(f"Error reading file: {e}")


def read_email_from_stdin() -> str:
    """Read email content from stdin.

    Returns:
        Email content as string
    """
    stdin = sys.stdin.read()

    if not stdin.strip():
        raise ValueError("No input provided via stdin")

    return stdin


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        prog='phishing-analyzer',
        description='Phishing Email Analyzer - Extract IoCs and enrich with threat intelligence',
        epilog='''
Examples:
  %(prog)s -f email.eml
  %(prog)s -f email.eml --format json -o result.json
  %(prog)s -f email.eml --format csv -o result.csv
  %(prog)s -f email.eml --format html -o result.html
  %(prog)s -f email.eml -v
  %(prog)s -f email.msg
  cat email.eml | %(prog)s -
  %(prog)s --gui

Supported formats: json, cli, markdown, csv, html

Environment Variables:
  VIRUSTOTAL_API_KEY    VirusTotal API key (optional)
  ALIENVAULT_API_KEY     AlienVault OTX API key (optional)
        '''.replace('%(prog)s', 'phishing-analyzer')
    )

    parser.add_argument(
        'input',
        nargs='?',
        help='Email file path or "-" for stdin'
    )

    parser.add_argument(
        '-f', '--file',
        dest='file',
        help='Email file to analyze (.eml, .msg, or .txt)'
    )

    parser.add_argument(
        '-o', '--output',
        dest='output',
        help='Output file (default: stdout)'
    )

    parser.add_argument(
        '--format',
        dest='format',
        choices=['json', 'cli', 'markdown', 'csv', 'html'],
        default='cli',
        help='Output format (default: cli)'
    )

    parser.add_argument(
        '--no-colors',
        dest='no_colors',
        action='store_true',
        help='Disable colored output'
    )

    parser.add_argument(
        '-v', '--verbose',
        dest='verbose',
        action='store_true',
        help='Show detailed output'
    )

    parser.add_argument(
        '--gui',
        dest='gui',
        action='store_true',
        help='Launch GUI (Streamlit)'
    )

    parser.add_argument(
        '--no-enrich',
        dest='no_enrich',
        action='store_true',
        help='Skip threat intelligence enrichment'
    )

    parser.add_argument(
        '--virustotal-key',
        dest='virustotal_key',
        help='VirusTotal API key (or set VIRUSTOTAL_API_KEY env)'
    )

    parser.add_argument(
        '--alienvault-key',
        dest='alienvault_key',
        help='AlienVault OTX API key (or setALIENVAULT_API_KEY env)'
    )

    parser.add_argument(
        '--timeout',
        dest='timeout',
        type=int,
        default=30,
        help='API request timeout in seconds (default: 30)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    return parser.parse_args()


def main() -> int:
    """Main CLI entry point.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    args = parse_arguments()

    if args.gui:
        return launch_gui()

    input_source = args.input or args.file

    if not input_source and sys.stdin.isatty():
        print("Error: No input provided. Use -f or pass via stdin.", file=sys.stderr)
        print("Run with --help for usage information.", file=sys.stderr)
        return 1

    try:
        if input_source == '-':
            email_content = read_email_from_stdin()
        elif input_source:
            email_content = read_email_from_file(input_source)
        elif args.file:
            email_content = read_email_from_file(args.file)
        else:
            email_content = read_email_from_stdin()

    except (FileNotFoundError, IOError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    virustotal_key = args.virustotal_key or os.environ.get('VIRUSTOTAL_API_KEY')
    alienvault_key = args.alienvault_key or os.environ.get('ALIENVAULT_API_KEY')

    config = AnalysisConfig(
        virustotal_api_key=virustotal_key,
        alienvault_api_key=alienvault_key,
        enrich_domains=not args.no_enrich,
        enrich_urls=not args.no_enrich,
        enrich_hashes=not args.no_enrich,
        enrich_ips=not args.no_enrich,
        timeout=args.timeout,
        verbose=args.verbose
    )

    try:
        with PhishingEmailAnalyzer(config) as analyzer:
            result = analyzer.analyze_email(email_content)
            output = analyzer.get_output(result)

            if args.format == 'json':
                formatter = JSONFormatter()
                formatted = formatter.format(output)
            elif args.format == 'markdown':
                formatter = MarkdownFormatter()
                formatted = formatter.format(output)
            elif args.format == 'csv':
                formatter = CSVFormatter()
                formatted = formatter.format(output)
            elif args.format == 'html':
                formatter = HTMLReportFormatter()
                formatted = formatter.format(output)
            else:
                formatter = CLIFormatter(
                    use_colors=not args.no_colors,
                    verbose=args.verbose
                )
                formatted = formatter.format(output)

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(formatted)
                print(f"Results written to: {args.output}")
            else:
                print(formatted)

            return 0

    except KeyboardInterrupt:
        print("\nAnalysis interrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def launch_gui() -> int:
    """Launch Streamlit GUI.

    Returns:
        Exit code
    """
    try:
        import streamlit as st
    except ImportError:
        print("Error: Streamlit not installed.", file=sys.stderr)
        print("Install with: pip install streamlit", file=sys.stderr)
        return 1

    try:
        from gui.app import main as gui_main
        st.set_page_config(
            page_title="Phishing Email Analyzer",
            page_icon="🎣",
            layout="wide"
        )
        gui_main()
        return 0
    except Exception as e:
        print(f"Error launching GUI: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())