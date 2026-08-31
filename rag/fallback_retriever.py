"""Lightweight in-memory keyword/lexical fallback retriever for SOC playbooks."""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("soc.rag.fallback")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PLAYBOOK_DIR = PROJECT_ROOT / "knowledge" / "playbooks"

_STOPWORDS: Set[str] = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "as", "at", "be", "because", "been", "before", "being", "below",
    "between", "both", "but", "by", "can", "did", "do", "does", "doing", "don",
    "down", "during", "each", "few", "for", "from", "further", "had", "has",
    "have", "having", "he", "her", "here", "hers", "herself", "him", "himself",
    "his", "how", "i", "if", "in", "into", "is", "it", "its", "itself", "just",
    "me", "more", "most", "my", "myself", "no", "nor", "not", "now", "of", "off",
    "on", "once", "only", "or", "other", "our", "ours", "ourselves", "out",
    "over", "own", "s", "same", "she", "should", "so", "some", "such", "t",
    "than", "that", "the", "their", "theirs", "them", "themselves", "then",
    "there", "these", "they", "this", "those", "through", "to", "too", "under",
    "until", "up", "very", "was", "we", "were", "what", "when", "where", "which",
    "while", "who", "whom", "why", "will", "with", "you", "your", "yours",
    "yourself", "yourselves",
}

_ATTACK_KEYWORD_MAP: Dict[str, List[str]] = {
    "brute_force_response.md": ["brute", "force", "password", "guessing", "spraying", "t1110", "t1110.001", "t1110.003", "auth_failure"],
    "account_compromise_response.md": ["compromise", "compromised", "takeover", "valid", "accounts", "t1078", "auth_success"],
    "privilege_escalation_response.md": ["privilege", "escalation", "sudo", "root", "admin", "elevated", "t1078.003", "priv_change"],
    "lateral_movement_response.md": ["lateral", "movement", "rdp", "ssh", "psexec", "smb", "pivot", "t1021", "t1021.001", "t1021.002"],
    "credential_dumping_response.md": ["credential", "dumping", "lsass", "mimikatz", "shadow", "sam", "ntds", "t1003", "t1003.001"],
}


def _tokenize(text: str) -> List[str]:
    """Tokenize and normalize text into lowercase words/terms."""
    tokens = re.findall(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", text.lower())
    return [t for t in tokens if len(t) > 1 and t not in _STOPWORDS]


class PlaybookChunk:
    """A searchable slice of an incident response playbook."""

    def __init__(self, text: str, title: str, filename: str, section: str = ""):
        self.text = text
        self.title = title
        self.filename = filename
        self.section = section
        self.tokens = _tokenize(text)
        self.title_tokens = _tokenize(title)
        self.token_set = set(self.tokens)


class FallbackRetriever:
    """Local, zero-dependency keyword and topic-guided retriever over Markdown playbooks."""

    def __init__(self, playbook_dir: Optional[Path] = None):
        self.playbook_dir = playbook_dir or DEFAULT_PLAYBOOK_DIR
        self._chunks: List[PlaybookChunk] = []
        self._loaded: bool = False

    def load_playbooks(self) -> None:
        """Load and index all Markdown playbooks in the designated directory."""
        self._chunks = []
        if not self.playbook_dir.exists() or not self.playbook_dir.is_dir():
            logger.warning("Playbook directory does not exist: %s", self.playbook_dir)
            self._loaded = True
            return

        for md_path in sorted(self.playbook_dir.glob("*.md")):
            try:
                content = md_path.read_text(encoding="utf-8")
                self._index_file(md_path.name, content)
            except Exception as exc:
                logger.warning("Failed to read playbook file %s: %s", md_path, exc)

        self._loaded = True
        logger.info("FallbackRetriever loaded %d chunks from %s", len(self._chunks), self.playbook_dir)

    def _index_file(self, filename: str, content: str) -> None:
        lines = content.splitlines()
        doc_title = filename.replace("_", " ").replace(".md", "").title()

        # Extract main H1 header if present
        for line in lines:
            if line.startswith("# "):
                doc_title = line.lstrip("# ").strip()
                break

        # Slicing by markdown sections (## Section)
        sections: List[tuple[str, str]] = []
        current_header = "Overview"
        current_lines: List[str] = []

        for line in lines:
            if line.startswith("## "):
                if current_lines:
                    sections.append((current_header, "\n".join(current_lines).strip()))
                    current_lines = []
                current_header = line.lstrip("# ").strip()
            current_lines.append(line)

        if current_lines:
            sections.append((current_header, "\n".join(current_lines).strip()))

        # If sections extracted, index each section; also index whole doc if short
        for sec_name, sec_text in sections:
            if len(sec_text.strip()) > 10:
                chunk_title = f"{doc_title} — {sec_name}"
                self._chunks.append(PlaybookChunk(sec_text, chunk_title, filename, sec_name))

        # Also create windowed chunks for full text coverage
        chunk_size = 500
        overlap = 100
        start = 0
        while start < len(content):
            end = start + chunk_size
            chunk_slice = content[start:end].strip()
            if len(chunk_slice) > 10:
                self._chunks.append(PlaybookChunk(chunk_slice, doc_title, filename))
            start = end - overlap

    def retrieve(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Rank and return the most relevant playbook chunks for the given query."""
        if not self._loaded:
            self.load_playbooks()

        if not query or not query.strip() or not self._chunks:
            return []

        q_tokens = _tokenize(query)
        if not q_tokens:
            return []

        q_token_set = set(q_tokens)
        q_lower = query.lower()

        scored_chunks: List[tuple[float, PlaybookChunk]] = []

        for chunk in self._chunks:
            score = 0.0

            # 1. Exact term matches
            overlap_count = len(q_token_set.intersection(chunk.token_set))
            if overlap_count > 0:
                score += overlap_count * 2.0

            # 2. Term frequency in chunk text
            for t in q_tokens:
                tf = chunk.tokens.count(t)
                if tf > 0:
                    score += math.log(1.0 + tf) * 1.5

            # 3. Title token match bonus
            title_overlap = len(q_token_set.intersection(set(chunk.title_tokens)))
            if title_overlap > 0:
                score += title_overlap * 4.0

            # 4. Domain attack-type intent bonus
            attack_keywords = _ATTACK_KEYWORD_MAP.get(chunk.filename, [])
            for kw in attack_keywords:
                if kw in q_lower:
                    score += 5.0
                    break

            # 5. Section intent boost (e.g. containment query -> containment section)
            sec_lower = chunk.section.lower()
            if any(term in q_lower for term in ("contain", "remediat", "action", "step", "mitigat")) and "contain" in sec_lower:
                score += 3.0
            if any(term in q_lower for term in ("investigat", "indicator", "detect", "scope")) and "investigat" in sec_lower:
                score += 3.0

            if score > 0.5:
                scored_chunks.append((score, chunk))

        # Sort by score descending
        scored_chunks.sort(key=lambda x: x[0], reverse=True)

        # Deduplicate and return top_k
        results: List[Dict[str, Any]] = []
        seen_texts: Set[str] = set()

        for score, chunk in scored_chunks:
            # Clean preview text for uniqueness check
            preview = chunk.text[:120].strip()
            if preview in seen_texts:
                continue
            seen_texts.add(preview)

            results.append({
                "text": chunk.text,
                "title": chunk.title,
                "source": "playbook",
                "file": chunk.filename,
                "score": round(score, 3),
            })

            if len(results) >= max(top_k, 1):
                break

        return results


_fallback_retriever: Optional[FallbackRetriever] = None


def get_fallback_retriever() -> FallbackRetriever:
    global _fallback_retriever
    if _fallback_retriever is None:
        _fallback_retriever = FallbackRetriever()
    return _fallback_retriever
