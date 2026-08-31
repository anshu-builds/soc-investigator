from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any, List, Optional, Protocol

from backend.services.text_prep import prepare_for_speech


class SarvamTTSError(Exception):
    """Normalized error for any Sarvam TTS failure — network, auth, quota,
    or malformed response. Callers (the FastAPI route) should catch this
    specifically and degrade to 'text answer only, audio unavailable'
    rather than letting a raw provider exception surface.
    """


@dataclass
class TTSClip:
    audio_bytes: bytes
    sequence: int  # 0-indexed order for sequential playback on the client


class SpeechClient(Protocol):
    """Structural type for whatever Sarvam client is injected — lets tests
    supply a fake without importing the real `sarvamai` package."""

    def convert(self, *, text: str, model: str, language_code: str,
                speaker: str, output_audio_codec: str,
                speech_sample_rate: int, pace: float = 1.0) -> Any: ...


def get_client(api_key: Optional[str] = None) -> SpeechClient:
    """Constructs the real Sarvam client. Imported lazily so this module
    (and its unit tests) don't require the `sarvamai` package to be
    installed unless this specific function is actually called."""
    from sarvamai import SarvamAI

    api_key = api_key or os.environ.get("SARVAM_API_KEY")
    if not api_key:
        raise SarvamTTSError(
            "SARVAM_API_KEY is not configured. TTS is unavailable."
        )
    client = SarvamAI(api_subscription_key=api_key)
    return client.text_to_speech


def synthesize(
    raw_text: str,
    client: Optional[SpeechClient] = None,
    language: Optional[str] = None,
    speaker: Optional[str] = None,
    api_key: Optional[str] = None,
) -> List[TTSClip]:
    """Sanitize + chunk the given text, then synthesize each chunk into a
    separate audio clip. Returns clips in playback order rather than trying
    to concatenate WAV byte streams (which requires real header surgery) —
    the frontend plays them back-to-back via onended chaining instead.

    Raises SarvamTTSError on any failure. Never raises for empty input —
    returns an empty list instead, since "nothing to say" isn't an error.
    """
    chunks = prepare_for_speech(raw_text)
    if not chunks:
        return []

    resolved_client = client or get_client(api_key=api_key)
    language_code = language or os.environ.get("SARVAM_TTS_LANGUAGE", "en-IN")
    speaker_name = speaker or os.environ.get("SARVAM_TTS_SPEAKER", "shubh")

    clips: List[TTSClip] = []
    for i, chunk_text in enumerate(chunks):
        try:
            result = resolved_client.convert(
                text=chunk_text,
                model="bulbul:v3",
                language_code=language_code,
                speaker=speaker_name,
                output_audio_codec="wav",
                speech_sample_rate=24000,
            )
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any
            # provider-side failure (network, auth, quota, 5xx) must be
            # normalized to SarvamTTSError so the route can degrade
            # gracefully instead of leaking a provider-specific exception.
            raise SarvamTTSError(f"Sarvam TTS request failed: {exc}") from exc

        audios = getattr(result, "audios", None)
        if not audios:
            raise SarvamTTSError("Sarvam TTS returned no audio data.")

        try:
            audio_bytes = base64.b64decode(audios[0])
        except Exception as exc:  # noqa: BLE001
            raise SarvamTTSError(f"Could not decode Sarvam audio response: {exc}") from exc

        clips.append(TTSClip(audio_bytes=audio_bytes, sequence=i))

    return clips
