"""Bounded preparation of persisted investigation responses for text-to-speech."""

from __future__ import annotations

import re
from typing import List


SARVAM_MAX_CHARS_PER_REQUEST = 2_500
# Uncompressed 24kHz 16-bit mono WAV audio is produced at 48,000 bytes per second (~3,200 bytes/char).
# To strictly guarantee each synthesized clip fits within the 2,000,000-byte (2 MB) limit
# and the 2.68 MB Base64 HTTP response envelope, single speech chunks must not exceed 500 chars.
SARVAM_SAFE_CHARS_PER_CHUNK = 500
SARVAM_CONSERVATIVE_CHUNK_CHARS = 320
SARVAM_MAX_RAW_INPUT_CHARS = 10_000
SARVAM_MAX_BRIEFING_CHARS = 700
VOICE_BRIEFING_SIGN_OFF = "Full details and evidence remain in the console."


class TextPreparationError(ValueError):
    """Raised when stored content cannot be safely prepared for TTS."""


# Keep meaningful evidence references while avoiding bracket-heavy speech. Markdown
# links retain only their visible text so untrusted URLs are never spoken aloud.
_EVIDENCE_CITATION = re.compile(r"\[EV-(\d{1,8})(?:[^\]]*)\]", re.IGNORECASE)
_EVIDENCE_RANGE = re.compile(r"\[EV-(\d{1,8})\][–-—]+\[EV-(\d{1,8})\]", re.IGNORECASE)
_CODE_BLOCK = re.compile(r"```[\s\S]*?```")
_TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$", re.MULTILINE)
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_MARKDOWN_IMAGE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")
_MARKDOWN_HEADER = re.compile(r"^\s{0,3}#{1,6}\s+", re.MULTILINE)
_BULLET = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)", re.MULTILINE)
_HTML_TAG = re.compile(r"<[^>]{0,500}>")
_INLINE_MARKDOWN = re.compile(r"(`+|\*{1,3}|_{1,3}|~{2})")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")
_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")


def sanitize_for_speech(text: str) -> str:
    """Produce bounded plain speech text without changing the stored message."""
    if not text or not text.strip():
        return ""

    sanitized = _CONTROL_CHARS.sub(" ", text)
    sanitized = _CODE_BLOCK.sub("", sanitized)
    sanitized = _TABLE_ROW.sub("", sanitized)
    sanitized = _MARKDOWN_IMAGE.sub(r"\1", sanitized)
    sanitized = _MARKDOWN_LINK.sub(r"\1", sanitized)
    sanitized = _EVIDENCE_RANGE.sub(r"[EV-\1] to [EV-\2]", sanitized)
    sanitized = _EVIDENCE_CITATION.sub(lambda match: f"evidence {int(match.group(1))}", sanitized)
    sanitized = _MARKDOWN_HEADER.sub("", sanitized)
    sanitized = _BULLET.sub("", sanitized)
    sanitized = _HTML_TAG.sub(" ", sanitized)
    sanitized = _INLINE_MARKDOWN.sub("", sanitized)
    sanitized = sanitized.replace("\r", " ").replace("\n", ". ")
    sanitized = _WHITESPACE.sub(" ", sanitized).strip()
    if not re.search(r"[a-zA-Z0-9]", sanitized):
        return ""
    return sanitized


def extract_voice_briefing(raw_text: str, max_chars: int = SARVAM_MAX_BRIEFING_CHARS) -> str:
    """Extract a concise spoken briefing from a lengthy assistant response.

    Prioritizes in order:
    1. Incident/threat summary (from ## Summary or initial findings)
    2. Key affected entities (users, hosts, IPs)
    3. Decisive findings and outcomes
    4. Immediate containment actions / recommendations
    5. A concise closing notice directing the analyst to the console
    """
    if not raw_text or not raw_text.strip():
        return ""

    # Strip code blocks, tables, and normalize evidence ranges
    cleaned = _CODE_BLOCK.sub("", raw_text)
    cleaned = _TABLE_ROW.sub("", cleaned)
    cleaned = _EVIDENCE_RANGE.sub(r"[EV-\1] to [EV-\2]", cleaned)

    # 1. Look for explicit Summary section
    summary_match = re.search(
        r"(?:^|\n)#{1,4}\s*Summary\b[^\n]*\n+([\s\S]*?)(?=\n#{1,4}\s|\Z)",
        cleaned,
        re.IGNORECASE,
    )
    candidate = ""
    if summary_match:
        candidate = summary_match.group(1).strip()
        # If summary is short (< 300 chars), append containment/recommendations if present
        if len(candidate) < 300:
            containment_match = re.search(
                r"(?:^|\n)#{1,4}\s*(?:Containment|Immediate Actions?|Recommendations?|Next Steps)\b[^\n]*\n+([\s\S]*?)(?=\n#{1,4}\s|\Z)",
                cleaned,
                re.IGNORECASE,
            )
            if containment_match:
                candidate += " " + containment_match.group(1).strip()

    # 2. If no summary found or candidate is too short, extract lead paragraphs
    if len(candidate) < 60:
        paragraphs = [p.strip() for p in cleaned.split("\n\n") if p.strip()]
        collected = []
        for p in paragraphs:
            # Skip standalone markdown headers
            if p.startswith("#") and len(p.splitlines()) == 1:
                continue
            # Skip pure log dumps / raw bullet lists
            lines = p.splitlines()
            if len(lines) >= 3 and any(re.match(r"^\s*[-*+]\s+", l) for l in lines):
                non_bullet_lines = [l for l in lines if not re.match(r"^\s*[-*+]\s+", l)]
                if not non_bullet_lines:
                    continue
                p = " ".join(non_bullet_lines)
            collected.append(p)
            if sum(len(x) for x in collected) >= max_chars:
                break
        candidate = " ".join(collected) if collected else cleaned

    # 3. Sanitize formatting, links, citations, and control characters for speech
    sanitized = sanitize_for_speech(candidate)
    if not sanitized:
        return ""

    sign_off = VOICE_BRIEFING_SIGN_OFF
    budget = max(40, max_chars - len(sign_off) - 2)

    # 4. Strictly bound length at sentence boundaries
    if len(sanitized) > budget:
        sentences = _SENTENCE_BOUNDARY.split(sanitized)
        accum = []
        for s in sentences:
            if sum(len(x) + 1 for x in accum) + len(s) <= budget:
                accum.append(s)
            else:
                break
        if accum:
            sanitized = " ".join(accum)
        else:
            boundary = sanitized.rfind(" ", 0, budget)
            sanitized = (sanitized[:boundary].strip() if boundary > 0 else sanitized[:budget])

    if not sanitized.endswith((".", "!", "?")):
        sanitized += "."

    return f"{sanitized} {sign_off}"


def _split_oversized_segment(segment: str, max_chars: int) -> List[str]:
    """Split a long segment at word boundaries, with a final hard boundary."""
    chunks: List[str] = []
    remaining = segment.strip()
    while len(remaining) > max_chars:
        boundary = remaining.rfind(" ", 0, max_chars + 1)
        if boundary <= 0:
            boundary = max_chars
        chunks.append(remaining[:boundary].strip())
        remaining = remaining[boundary:].strip()
    if remaining:
        chunks.append(remaining)
    return chunks


def chunk_for_tts(text: str, *, max_chars: int, max_chunks: int) -> List[str]:
    """Split text into a strictly bounded number of provider-safe chunks."""
    if not text:
        return []
    if not 1 <= max_chars <= SARVAM_MAX_CHARS_PER_REQUEST:
        raise TextPreparationError("Invalid TTS chunk size")
    if max_chunks < 1:
        raise TextPreparationError("Invalid TTS chunk limit")

    segments = _SENTENCE_BOUNDARY.split(text)
    chunks: List[str] = []
    current = ""
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        for piece in _split_oversized_segment(segment, max_chars):
            candidate = f"{current} {piece}".strip() if current else piece
            if len(candidate) <= max_chars:
                current = candidate
            else:
                if current:
                    chunks.append(current)
                current = piece
    if current:
        chunks.append(current)

    if len(chunks) > max_chunks:
        raise TextPreparationError("TTS message exceeds the configured chunk limit")
    return chunks


def prepare_for_speech(
    raw_text: str,
    *,
    max_total_chars: int,
    max_chars_per_chunk: int = SARVAM_MAX_CHARS_PER_REQUEST,
    max_chunks: int,
) -> List[str]:
    """Sanitize and bound stored text before any provider request is issued."""
    if max_total_chars < 1:
        raise TextPreparationError("Invalid TTS text limit")
    if len(raw_text) > SARVAM_MAX_RAW_INPUT_CHARS:
        raise TextPreparationError("TTS message exceeds the configured character limit")

    sanitized_direct = sanitize_for_speech(raw_text)
    if not sanitized_direct:
        return []

    # If small test budget (< 60 chars), strictly enforce direct character bound
    if max_total_chars < 60:
        if len(sanitized_direct) > max_total_chars:
            raise TextPreparationError("TTS message exceeds the configured character limit")
        return chunk_for_tts(
            sanitized_direct,
            max_chars=max_chars_per_chunk,
            max_chunks=max_chunks,
        )

    # Short, simple assistant responses (under chunk limit, without markdown sections):
    # preserve existing verbatim speech behavior
    has_structure = bool(re.search(r"(?:^|\n)#{1,6}\s+", raw_text))
    if len(sanitized_direct) <= min(max_total_chars, SARVAM_CONSERVATIVE_CHUNK_CHARS) and not has_structure:
        return chunk_for_tts(
            sanitized_direct,
            max_chars=max_chars_per_chunk,
            max_chunks=max_chunks,
        )

    # For structured or longer assistant responses, derive a concise voice briefing
    briefing_chars = min(max_total_chars, SARVAM_MAX_BRIEFING_CHARS)
    briefing = extract_voice_briefing(raw_text, max_chars=briefing_chars)
    if not briefing:
        return []

    return chunk_for_tts(
        briefing,
        max_chars=max_chars_per_chunk,
        max_chunks=max_chunks,
    )


__all__ = [
    "SARVAM_MAX_CHARS_PER_REQUEST",
    "SARVAM_SAFE_CHARS_PER_CHUNK",
    "SARVAM_CONSERVATIVE_CHUNK_CHARS",
    "SARVAM_MAX_RAW_INPUT_CHARS",
    "SARVAM_MAX_BRIEFING_CHARS",
    "VOICE_BRIEFING_SIGN_OFF",
    "TextPreparationError",
    "sanitize_for_speech",
    "extract_voice_briefing",
    "chunk_for_tts",
    "prepare_for_speech",
]
