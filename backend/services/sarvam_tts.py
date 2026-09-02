"""Bounded async client for Sarvam's fixed text-to-speech REST endpoint."""

from __future__ import annotations

import base64
import binascii
import json
import logging
from dataclasses import dataclass
from typing import List, Optional

import httpx

from backend.security.url_validation import SafeAsyncClient, SSRFSecurityError, read_bounded_response
from backend.services.text_prep import (
    SARVAM_CONSERVATIVE_CHUNK_CHARS,
    SARVAM_MAX_CHARS_PER_REQUEST,
    TextPreparationError,
    prepare_for_speech,
)


logger = logging.getLogger("soc.tts.sarvam")

SARVAM_TRUSTED_HOST = "api.sarvam.ai"
SARVAM_TTS_ENDPOINT = "https://api.sarvam.ai/text-to-speech"
_RESPONSE_OVERHEAD_BYTES = 16 * 1024


class SarvamTTSError(RuntimeError):
    """A normalized provider/configuration failure safe for the API layer."""


@dataclass(frozen=True)
class TTSClip:
    audio_bytes: bytes
    sequence: int


def _max_encoded_response_bytes(max_audio_bytes: int) -> int:
    # Base64 expands data by at most 4/3; reserve a small bounded JSON envelope.
    return ((max_audio_bytes + 2) // 3) * 4 + _RESPONSE_OVERHEAD_BYTES


async def _request_clip(
    client: httpx.AsyncClient,
    *,
    text: str,
    api_key: str,
    language: str,
    speaker: str,
    max_audio_bytes: int,
) -> bytes:
    if len(text) > SARVAM_MAX_CHARS_PER_REQUEST:
        raise SarvamTTSError("Prepared text exceeds the provider limit")

    payload = {
        "model": "bulbul:v3",
        "text": text,
        "language_code": language,
        "speaker": speaker,
        "output_audio_codec": "wav",
        "speech_sample_rate": 24000,
    }
    try:
        async with client.stream(
            "POST",
            SARVAM_TTS_ENDPOINT,
            headers={"api-subscription-key": api_key, "Accept": "application/json"},
            json=payload,
        ) as response:
            if response.status_code != 200:
                logger.warning("Sarvam TTS returned HTTP %d", response.status_code)
                raise SarvamTTSError("Sarvam TTS rejected the request")
            raw_response = await read_bounded_response(
                response,
                max_bytes=_max_encoded_response_bytes(max_audio_bytes),
            )
    except SarvamTTSError:
        raise
    except (httpx.HTTPError, SSRFSecurityError) as exc:
        logger.warning("Sarvam TTS request failed: %s", type(exc).__name__)
        raise SarvamTTSError("Sarvam TTS request failed") from exc

    try:
        decoded_response = json.loads(raw_response.decode("utf-8"))
        audios = decoded_response.get("audios") if isinstance(decoded_response, dict) else None
        encoded_audio = audios[0] if isinstance(audios, list) and audios else None
        if not isinstance(encoded_audio, str):
            raise ValueError("missing audio")
        audio = base64.b64decode(encoded_audio, validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, binascii.Error) as exc:
        logger.warning("Sarvam TTS returned an invalid audio response")
        raise SarvamTTSError("Sarvam TTS returned invalid audio") from exc

    if not audio or len(audio) > max_audio_bytes:
        logger.warning("Sarvam TTS audio exceeded configured clip bounds")
        raise SarvamTTSError("Sarvam TTS audio exceeded configured limits")
    return audio


# Uncompressed 24kHz 16-bit mono WAV audio is produced at 48,000 bytes/sec (~3,200 - 3,700 bytes/char).
# Base64 expansion adds 1.33x (~4,300 - 5,000 bytes/char in HTTP JSON response).
# Using a conservative ratio of 6,250 bytes/char guarantees chunk sizes (e.g. 320 chars for 2MB clip)
# maintain a ~39% safety margin below both max_audio_bytes_per_clip and max_encoded_response_bytes.
SARVAM_AUDIO_BYTES_PER_CHAR_RATIO = 6_250


async def synthesize(
    raw_text: str,
    *,
    api_key: str,
    language: str,
    speaker: str,
    timeout_seconds: float,
    max_total_chars: int,
    max_chunks: int,
    max_audio_bytes_per_clip: int,
    max_total_audio_bytes: int,
    client: Optional[httpx.AsyncClient] = None,
) -> List[TTSClip]:
    """Prepare and synthesize bounded persisted text without retry amplification."""
    if not api_key:
        raise SarvamTTSError("Sarvam TTS is not configured")
    if timeout_seconds <= 0:
        raise SarvamTTSError("Invalid TTS timeout")
    if max_audio_bytes_per_clip < 1 or max_total_audio_bytes < max_audio_bytes_per_clip:
        raise SarvamTTSError("Invalid TTS audio limits")

    chunk_size = (
        min(SARVAM_CONSERVATIVE_CHUNK_CHARS, max(100, int(max_audio_bytes_per_clip / SARVAM_AUDIO_BYTES_PER_CHAR_RATIO)))
        if max_audio_bytes_per_clip >= 100_000
        else SARVAM_CONSERVATIVE_CHUNK_CHARS
    )
    chunks = prepare_for_speech(
        raw_text,
        max_total_chars=max_total_chars,
        max_chars_per_chunk=chunk_size,
        max_chunks=max_chunks,
    )
    if not chunks:
        return []

    owns_client = client is None
    resolved_client = client or SafeAsyncClient(
        timeout=timeout_seconds,
        max_response_size=_max_encoded_response_bytes(max_audio_bytes_per_clip),
        allowed_hosts={SARVAM_TRUSTED_HOST},
        allowed_schemes=("https",),
    )
    clips: List[TTSClip] = []
    total_audio_bytes = 0
    try:
        for sequence, chunk in enumerate(chunks):
            audio = await _request_clip(
                resolved_client,
                text=chunk,
                api_key=api_key,
                language=language,
                speaker=speaker,
                max_audio_bytes=max_audio_bytes_per_clip,
            )
            total_audio_bytes += len(audio)
            if total_audio_bytes > max_total_audio_bytes:
                logger.warning("Sarvam TTS aggregate audio exceeded configured bounds")
                raise SarvamTTSError("Sarvam TTS audio exceeded configured limits")
            clips.append(TTSClip(audio_bytes=audio, sequence=sequence))
    finally:
        if owns_client:
            await resolved_client.aclose()
    return clips


__all__ = [
    "SARVAM_TRUSTED_HOST",
    "SARVAM_TTS_ENDPOINT",
    "SarvamTTSError",
    "TextPreparationError",
    "TTSClip",
    "synthesize",
]
