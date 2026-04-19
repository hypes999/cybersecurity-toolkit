"""Phishing Email Analyzer - Streamlit GUI.

A web-based graphical user interface for analyzing phishing emails
and visualizing threat intelligence results.
"""

import streamlit as st
import os
import sys

# Adicionar diretório raiz ao path para funcionar em qualquer SO
_app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from analyzer import PhishingEmailAnalyzer, AnalysisConfig
from output.formatters import AnalysisOutput, CLIFormatter


def main():
    """Main Streamlit app."""
    st.set_page_config(
        page_title="Phishing Email Analyzer",
        page_icon="🎣",
        layout="wide"
    )

    st.title("🎣 Phishing Email Analyzer")
    st.markdown("---")

    with st.sidebar:
        st.header("Configuration")

        st.subheader("API Keys")
        vt_key = st.text_input(
            "VirusTotal API Key",
            type="password",
            help="Get free key at virustotal.com",
            key="vt_key"
        )
        otx_key = st.text_input(
            "AlienVault OTX API Key",
            type="password",
            help="Optional - get at otx.alienvault.com",
            key="otx_key"
        )

        st.subheader("Options")
        enrich_enabled = st.checkbox("Enable Threat Intelligence", value=True, key="enrich")
        verbose = st.checkbox("Verbose Output", value=False, key="verbose")

        timeout = st.slider("Timeout (seconds)", 10, 120, 30, key="timeout")

    input_method = st.radio("Input Method", ["Text Input", "File Upload"], horizontal=True)

    email_content = ""

    if input_method == "Text Input":
        email_content = st.text_area(
            "Email Content",
            height=300,
            placeholder="Paste email content here (headers + body)..."
        )
    else:
        uploaded_file = st.file_uploader(
            "Upload Email File",
            type=['eml', 'txt', 'msg'],
            help="Upload .eml, .txt, or .msg file"
        )
        if uploaded_file:
            email_content = uploaded_file.getvalue().decode('utf-8', errors='ignore')

    col1, col2 = st.columns([1, 1])
    with col1:
        analyze_button = st.button("🔍 Analyze Email", type="primary", use_container_width=True)
    with col2:
        clear_button = st.button("🗑️ Clear", use_container_width=True)

    if clear_button:
        st.rerun()

    if analyze_button and email_content:
        with st.spinner("Analyzing email..."):
            try:
                config = AnalysisConfig(
                    virustotal_api_key=vt_key if vt_key else None,
                    alienvault_api_key=otx_key if otx_key else None,
                    enrich_domains=enrich_enabled,
                    enrich_urls=enrich_enabled,
                    enrich_hashes=enrich_enabled,
                    enrich_ips=enrich_enabled,
                    timeout=timeout,
                    verbose=verbose
                )

                with PhishingEmailAnalyzer(config) as analyzer:
                    result = analyzer.analyze_email(email_content)
                    output = analyzer.get_output(result)

                    display_results(output, verbose)

            except Exception as e:
                st.error(f"Error during analysis: {e}")

    elif analyze_button and not email_content:
        st.warning("Please provide email content to analyze.")


def display_results(output: AnalysisOutput, verbose: bool = False):
    """Display analysis results in Streamlit.

    Args:
        output: AnalysisOutput object
        verbose: Show detailed output
    """
    summary = output.summary
    threat_level = summary.get('threat_level', 'unknown')

    if threat_level == 'high':
        st.error(f"🚨 Threat Level: **{threat_level.upper()}**")
    elif threat_level == 'medium':
        st.warning(f"⚠️ Threat Level: **{threat_level.upper()}**")
    else:
        st.success(f"✅ Threat Level: **{threat_level.upper()}**")

    st.markdown("---")

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Summary",
        "✉️ Headers",
        "🔗 URLs",
        "🌐 Domains",
        "🔐 Hashes"
    ])

    with tab1:
        st.subheader("Summary")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("URLs", summary.get('urls_total', 0), summary.get('urls_malicious', 0))
        with col2:
            st.metric("Domains", summary.get('domains_total', 0), summary.get('domains_malicious', 0))
        with col3:
            st.metric("Hashes", summary.get('hashes_total', 0), summary.get('hashes_malicious', 0))
        with col4:
            st.metric("Emails", summary.get('emails_found', 0), None)

        st.markdown("### Authentication")
        auth = output.authentication
        auth_cols = st.columns(3)

        with auth_cols[0]:
            spf_passed = auth.get('spf', {}).get('passed', False)
            st.metric("SPF", "✅ Pass" if spf_passed else "❌ Fail")

        with auth_cols[1]:
            dkim_passed = auth.get('dkim', {}).get('passed', False)
            st.metric("DKIM", "✅ Pass" if dkim_passed else "❌ Fail")

        with auth_cols[2]:
            dmarc_passed = auth.get('dmarc', {}).get('passed', False)
            st.metric("DMARC", "✅ Pass" if dmarc_passed else "❌ Fail")

    with tab2:
        st.subheader("Email Headers")

        headers = output.headers
        if headers:
            for key, value in headers.items():
                if value:
                    st.text_input(key.replace('_', ' ').title(), value, disabled=True)
        else:
            st.info("No headers found")

    with tab3:
        st.subheader(f"Extracted URLs ({len(output.urls)})")

        if output.urls:
            for url_data in output.urls:
                with st.container():
                    malicious = url_data.get('is_malicious', False)
                    suspicious = url_data.get('is_suspicious', False)

                    if malicious:
                        st.error(f"❌ {url_data.get('url', '')}")
                    elif suspicious:
                        st.warning(f"⚠️ {url_data.get('url', '')}")
                    else:
                        st.success(f"✅ {url_data.get('url', '')}")

                    if verbose:
                        col1, col2 = st.columns(2)
                        with col1:
                            st.caption(f"Domain: {url_data.get('domain', '-')}")
                        with col2:
                            threat = url_data.get('threat_intel', '-')
                            if threat:
                                st.caption(f"Threat: {threat}")

                    st.divider()
        else:
            st.info("No URLs found")

    with tab4:
        st.subheader(f"Extracted Domains ({len(output.domains)})")

        if output.domains:
            for domain_data in output.domains:
                malicious = domain_data.get('is_malicious', False)
                suspicious = domain_data.get('suspicious_patterns', [])

                if malicious:
                    st.error(f"❌ {domain_data.get('domain', '')}")
                elif suspicious:
                    st.warning(f"⚠️ {domain_data.get('domain', '')}")
                else:
                    st.success(f"✅ {domain_data.get('domain', '')}")

                if verbose and suspicious:
                    st.caption(f"Suspicious: {', '.join(suspicious)}")

                st.divider()
        else:
            st.info("No domains found")

    with tab5:
        st.subheader(f"Extracted Hashes ({len(output.hashes)})")

        if output.hashes:
            for hash_data in output.hashes:
                malicious = hash_data.get('is_malicious', False)
                hash_type = hash_data.get('hash_type', '').upper()
                hash_value = hash_data.get('hash_value', '')

                if malicious:
                    st.error(f"❌ {hash_type}: {hash_value}")
                else:
                    st.success(f"✅ {hash_type}: {hash_value}")

                st.divider()
        else:
            st.info("No hashes found")

    if output.errors:
        st.markdown("---")
        st.subheader("Errors")

        for error in output.errors:
            st.error(error)

    st.markdown("---")
    st.caption(f"Analysis completed at {output.timestamp}")


if __name__ == "__main__":
    main()