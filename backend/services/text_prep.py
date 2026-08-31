from __future__ import annotations

import re
from typing import List

# Matches the citation formats your system actually produces:
#   [EV-003]                          — normal, verified citation
#   [EV-003⚠️UNVERIFIED]              — flagged by ai/evidence_linker.py when
#                                        the LLM cites evidence that doesn't
#                                        exist in the incident's evidence map
EVIDENCE_CITATION = re.compile(r"\[EV-(\d{3,})(⚠️UNVERIFIED)?\]")

MARKDOWN_HEADER = re.compile(r"^#{1,6}\s*(.+)$", re.MULTILINE)
BOLD = re.compile(r"\*\*(.+?)\*\*")
ITALIC = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
INLINE_CODE = re.compile(r"`([^`]+)`")
BULLET_MARKER = re.compile(r"^\s*[-*]\s+", re.MULTILINE)
NUMBERED_MARKER = re.compile(r"^\s*\d+\.\s+", re.MULTILINE)
HORIZONTAL_RULE = re.compile(r"^-{3,}\s*$", re.MULTILINE)
MULTI_WHITESPACE = re.compile(r"[ \t]+")
MULTI_NEWLINE = re.compile(r"\n{2,}")

# Sentence boundary: '.', '!', or '?' followed by whitespace and a capital
# letter, digit, or end of string — good enough for chunking English SOC
# report prose without a full NLP sentence splitter.
SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")

BULBUL_V3_REST_CHAR_LIMIT = 2500


def sanitize_for_speech(text: str) -> str:
    """Convert a structured investigation-chain Markdown response into plain
    prose suitable for TTS. This has no analogue in the original integration
    report, which assumed the LLM's raw output was already speakable — it
    isn't: it's headed sections, bold labels, bullet timelines, and bracketed
    evidence citations like [EV-003].
    """
    if not text:
        return ""

    result = text

    # Evidence citations: verbalize rather than strip, so a sentence like
    # "...consistent with [EV-003]" doesn't lose its point of reference.
    def _citation_repl(match: re.Match) -> str:
        number = str(int(match.group(1)))  # drop leading zeros: 003 -> 3
        if match.group(2):  # unverified flag was present
            return f" (evidence {number}, unverified)"
        return f" (evidence {number})"

    result = EVIDENCE_CITATION.sub(_citation_repl, result)

    # Headers: keep the header text as a short spoken transition, drop the
    # markdown hashes. "## Summary" -> "Summary."
    result = MARKDOWN_HEADER.sub(lambda m: f"{m.group(1).strip()}.", result)

    result = INLINE_CODE.sub(r"\1", result)
    result = BOLD.sub(r"\1", result)
    result = ITALIC.sub(r"\1", result)
    result = HORIZONTAL_RULE.sub("", result)
    result = BULLET_MARKER.sub("", result)
    result = NUMBERED_MARKER.sub("", result)

    result = MULTI_WHITESPACE.sub(" ", result)
    result = MULTI_NEWLINE.sub(". ", result)
    result = result.replace("\n", ". ")

    # Cleanup: collapse any double periods/spaces introduced by the
    # substitutions above (e.g. a header immediately followed by a
    # sentence that also ends in a period).
    result = re.sub(r"\.\s*\.", ".", result)
    result = re.sub(r"\s{2,}", " ", result)

    return result.strip()


def chunk_for_tts(
    text: str,
    max_chars: int = BULBUL_V3_REST_CHAR_LIMIT,
) -> List[str]:
    """Split sanitized text into chunks that each fit within the provider's
    REST character limit, breaking at sentence boundaries wherever possible
    so no chunk ends mid-sentence. Falls back to a hard split only for a
    single sentence that alone exceeds the limit (rare, but must not crash).
    """
    if not text:
        return []

    if len(text) <= max_chars:
        return [text]

    sentences = SENTENCE_BOUNDARY.split(text)
    chunks: List[str] = []
    current = ""

    for sentence in sentences:
        candidate = f"{current} {sentence}".strip() if current else sentence

        if len(candidate) <= max_chars:
            current = candidate
            continue

        if current:
            chunks.append(current)
            current = ""

        if len(sentence) <= max_chars:
            current = sentence
        else:
            # A single sentence exceeds the limit on its own — hard-split
            # at word boundaries rather than raising, so a long incident
            # narrative still produces playable (if less elegant) audio.
            chunks.extend(_hard_split(sentence, max_chars))

    if current:
        chunks.append(current)

    return chunks


def _hard_split(text: str, max_chars: int) -> List[str]:
    words = text.split(" ")
    chunks: List[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip() if current else word
        if len(candidate) <= max_chars:
            current = candidate
        else:
            if current:
                chunks.append(current)
            current = word
    if current:
        chunks.append(current)
    return chunks


def prepare_for_speech(
    raw_text: str,
    max_chars: int = BULBUL_V3_REST_CHAR_LIMIT,
) -> List[str]:
    """End-to-end: sanitize the LLM's Markdown output, then chunk it safely
    for the provider's per-request character limit. This is the single
    function the TTS service should call."""
    sanitized = sanitize_for_speech(raw_text)
    return chunk_for_tts(sanitized, max_chars=max_chars)
