"""Report generation security sanitizer.

Defends against stored XSS, HTML injection, Markdown table/heading injection,
unsafe URL schemes (javascript:, data:, vbscript:), client-side SSRF/tracking beacons,
and code-block breakouts in generated security incident reports.
"""

from __future__ import annotations

import html
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set

import bleach

# Allowed HTML tags for rendered HTML reports (strict allowlist)
REPORT_ALLOWED_TAGS: List[str] = [
    "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "br", "hr",
    "strong", "em", "u",
    "blockquote", "code", "pre",
    "ul", "ol", "li",
    "table", "thead", "tbody", "tr", "th", "td",
    "a", "span",
]

REPORT_ALLOWED_ATTRIBUTES: Dict[str, List[str]] = {
    "a": ["href", "title", "target", "rel"],
    "code": ["class"],
    "span": ["class"],
    "th": ["align"],
    "td": ["align"],
}

REPORT_ALLOWED_PROTOCOLS: List[str] = ["http", "https", "mailto"]

DANGEROUS_SCHEMES: Set[str] = {
    "javascript",
    "data",
    "vbscript",
    "file",
    "about",
    "blob",
    "filesystem",
}


def clean_control_characters(text: str) -> str:
    """Purge NULL bytes and unprintable control characters, preserving normal whitespace."""
    if not text:
        return ""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(text))


def is_dangerous_url(url: str) -> bool:
    """Detect dangerous URI schemes (javascript:, data:, etc.) even if obfuscated."""
    if not url:
        return False
    unescaped = html.unescape(url)
    try:
        unquoted = urllib.parse.unquote(unescaped)
    except Exception:
        unquoted = unescaped
    normalized = re.sub(r"[\x00-\x20\x7f]", "", unquoted).lower()

    for scheme in DANGEROUS_SCHEMES:
        if normalized.startswith(scheme + ":"):
            return True
    return False


def sanitize_text(val: Any) -> str:
    """HTML-escape untrusted plain text fields (usernames, IPs, titles, event descriptions).

    Guarantees that raw HTML elements like <script> or <img onerror=...> become harmless
    visible text (&lt;script&gt;) and cannot execute as active markup.
    """
    if val is None:
        return ""
    cleaned = clean_control_characters(str(val))
    return html.escape(cleaned, quote=True)


def sanitize_table_cell(val: Any) -> str:
    """Sanitize content for inclusion in a Markdown table cell.

    HTML-escapes tags, strips newlines (\\r, \\n), and escapes pipe characters (| -> \\|)
    to prevent table structure breakout or column injection.
    """
    if val is None:
        return ""
    escaped = sanitize_text(val)
    escaped = re.sub(r"[\r\n]+", " ", escaped)
    escaped = escaped.replace("|", "\\|")
    return escaped.strip()


def sanitize_code_block(val: Any) -> str:
    """Sanitize raw log samples inside Markdown fenced code blocks.

    Prevents code-block breakout by replacing triple backticks (```) with spaced backticks,
    and HTML-escapes content to ensure raw tags cannot execute even if fences fail.
    """
    if val is None:
        return ""
    cleaned = clean_control_characters(str(val))
    neutralized = cleaned.replace("```", "` ` `")
    return html.escape(neutralized)


def sanitize_markdown_prose(val: Any) -> str:
    """Sanitize natural-language Markdown prose (such as AI summaries and attack narratives).

    - Escapes raw HTML tags (<script>, <iframe>, <svg>, <style>, <form>, etc.)
    - Neutralizes dangerous link targets: [Click](javascript:alert(1)) -> [Click](#blocked-unsafe-scheme)
    - Neutralizes external Markdown images: ![alt](url) -> [alt (image blocked for security)]
    - Preserves legitimate Markdown formatting: **bold**, *italic*, lists, headings, and [EV-NNN] citations.
    """
    if val is None:
        return ""
    text = clean_control_characters(str(val))

    # 1. Escape any raw HTML tags
    escaped_html = bleach.clean(text, tags=[], strip=False, strip_comments=True)

    # 1b. Restore legitimate markdown blockquotes at line starts (^> or \n>)
    # While bleach correctly escapes HTML, line-start '>' in Markdown denotes a blockquote
    restored_quotes = escaped_html
    while re.search(r"((?:^|\n)>*)&gt;", restored_quotes):
        restored_quotes = re.sub(r"((?:^|\n)>*)&gt;", r"\1>", restored_quotes)

    # 2. Neutralize external images to prevent client-side SSRF and tracking beacons
    def neutralize_image(match):
        alt = match.group(1).strip()
        label = alt if alt else "Image"
        return f"[{label} (image blocked for security)]"

    cleaned_images = re.sub(r"!\[([^\]]*)\]\(((?:[^()]+|\([^()]*\))+)\)", neutralize_image, restored_quotes)

    # 3. Neutralize dangerous link schemes in markdown links: [label](target)
    pattern = r"\[([^\]]+)\]\(((?:[^()]+|\([^()]*\))+)\)"

    def sanitize_link(match):
        label = match.group(1)
        raw_target = match.group(2).strip()
        parts = raw_target.split(None, 1)
        target_url = parts[0].strip("<>")
        if is_dangerous_url(target_url):
            return f"[{label}](#blocked-unsafe-scheme)"
        return match.group(0)

    cleaned_links = re.sub(pattern, sanitize_link, cleaned_images)
    return cleaned_links


def render_report_to_html(markdown_content: str) -> str:
    """Convert sanitized Markdown to HTML and apply bleach HTML allowlist sanitization."""
    import markdown
    raw_html = markdown.markdown(
        markdown_content,
        extensions=["tables", "fenced_code", "nl2br"],
    )
    cleaned_html = bleach.clean(
        raw_html,
        tags=REPORT_ALLOWED_TAGS,
        attributes=REPORT_ALLOWED_ATTRIBUTES,
        protocols=REPORT_ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )
    return cleaned_html
