from __future__ import annotations

import base64

import httpx
import pytest

from backend.services.sarvam_tts import SARVAM_TTS_ENDPOINT, SarvamTTSError, synthesize


@pytest.mark.asyncio
async def test_synthesize_uses_fixed_endpoint_and_returns_bounded_audio():
    seen = {}
    encoded_audio = base64.b64encode(b"wav-bytes").decode("ascii")

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["key"] = request.headers["api-subscription-key"]
        return httpx.Response(200, json={"audios": [encoded_audio]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        clips = await synthesize(
            "A short assistant response.",
            api_key="unit-test-key",
            language="en-IN",
            speaker="shubh",
            timeout_seconds=5,
            max_total_chars=100,
            max_chunks=1,
            max_audio_bytes_per_clip=100,
            max_total_audio_bytes=100,
            client=client,
        )

    assert seen == {"url": SARVAM_TTS_ENDPOINT, "key": "unit-test-key"}
    assert [clip.audio_bytes for clip in clips] == [b"wav-bytes"]


@pytest.mark.asyncio
async def test_provider_error_and_oversized_response_do_not_expose_provider_body():
    async def error_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content="provider-secret=do-not-leak")

    async with httpx.AsyncClient(transport=httpx.MockTransport(error_handler)) as client:
        with pytest.raises(SarvamTTSError) as error:
            await synthesize(
                "Assistant response.", api_key="unit-test-key", language="en-IN", speaker="shubh",
                timeout_seconds=5, max_total_chars=100, max_chunks=1,
                max_audio_bytes_per_clip=100, max_total_audio_bytes=100, client=client,
            )
    assert "provider-secret" not in str(error.value)

    async def oversized_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-length": "999999"}, content=b"{}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(oversized_handler)) as client:
        with pytest.raises(SarvamTTSError):
            await synthesize(
                "Assistant response.", api_key="unit-test-key", language="en-IN", speaker="shubh",
                timeout_seconds=5, max_total_chars=100, max_chunks=1,
                max_audio_bytes_per_clip=100, max_total_audio_bytes=100, client=client,
            )


@pytest.mark.asyncio
async def test_total_audio_limit_is_enforced_across_multiple_chunks():
    encoded_audio = base64.b64encode(b"0123456789").decode("ascii")

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"audios": [encoded_audio]})

    text = f"{'A' * 1300}. {'B' * 1300}."
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(SarvamTTSError, match="configured limits"):
            await synthesize(
                text, api_key="unit-test-key", language="en-IN", speaker="shubh",
                timeout_seconds=5, max_total_chars=5000, max_chunks=3,
                max_audio_bytes_per_clip=10, max_total_audio_bytes=15, client=client,
            )


@pytest.mark.asyncio
async def test_sarvam_fixed_endpoint_accepted_and_attacker_urls_rejected():
    """Verify that the fixed Sarvam endpoint is accepted and arbitrary attacker URLs are rejected by SSRF."""
    from backend.security.url_validation import SSRFSecurityError, SafeAsyncClient, validate_url_ssrf
    from backend.services.sarvam_tts import SARVAM_TRUSTED_HOST, SARVAM_TTS_ENDPOINT

    # 1. Fixed Sarvam endpoint is accepted by validate_url_ssrf with trusted host allowlist
    validated = validate_url_ssrf(
        SARVAM_TTS_ENDPOINT,
        allowed_hosts={SARVAM_TRUSTED_HOST},
        allowed_schemes=("https",),
        resolve_dns=False,
    )
    assert validated.scheme == "https"
    assert validated.hostname == "api.sarvam.ai"

    # 2. Arbitrary attacker-controlled URLs are rejected by SSRF protection
    attacker_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8000/api/internal",
        "http://localhost/admin",
        "https://attacker-controlled.example.com/tts",
        "http://10.0.0.1/secrets",
        "https://api.sarvam.ai.attacker.com/tts",
    ]
    for url in attacker_urls:
        with pytest.raises(SSRFSecurityError):
            validate_url_ssrf(
                url,
                allowed_hosts={SARVAM_TRUSTED_HOST},
                allowed_schemes=("https",),
                resolve_dns=False,
            )

    # 3. SafeAsyncClient configured with Sarvam allowed_hosts blocks unauthorized destinations
    client = SafeAsyncClient(
        allowed_hosts={SARVAM_TRUSTED_HOST},
        transport=httpx.MockTransport(lambda req: httpx.Response(200)),
    )
    req = client.build_request("GET", "https://evil.com/leak")
    with pytest.raises(SSRFSecurityError):
        await client.send(req)
    await client.aclose()


def test_client_cannot_influence_provider_destination():
    """Verify that no caller-supplied URL parameter exists on the synthesize interface."""
    import inspect
    from backend.services.sarvam_tts import synthesize

    sig = inspect.signature(synthesize)
    # Ensure neither 'url' nor 'endpoint' nor 'host' is an accepted parameter
    assert "url" not in sig.parameters
    assert "endpoint" not in sig.parameters
    assert "host" not in sig.parameters


@pytest.mark.asyncio
async def test_redirect_to_non_allowlisted_host_is_rejected():
    """Verify that SafeAsyncClient rejects redirects to non-allowlisted hosts."""
    from backend.security.url_validation import SSRFSecurityError, SafeAsyncClient
    from backend.services.sarvam_tts import SARVAM_TRUSTED_HOST

    def redirect_handler(req: httpx.Request) -> httpx.Response:
        if "sarvam" in str(req.url):
            return httpx.Response(302, headers={"Location": "https://attacker.com/steal"})
        return httpx.Response(200)

    client = SafeAsyncClient(
        allowed_hosts={SARVAM_TRUSTED_HOST},
        transport=httpx.MockTransport(redirect_handler),
    )
    req = client.build_request("POST", "https://api.sarvam.ai/text-to-speech")
    with pytest.raises(SSRFSecurityError, match="not in the allowed hosts"):
        await client.send(req)
    await client.aclose()


@pytest.mark.asyncio
async def test_realistic_large_provider_content_length_is_rejected():
    """Verify that a realistic oversized Content-Length (like the observed 12.9MB response) is rejected."""
    from backend.services.sarvam_tts import _request_clip

    async def oversized_handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": "12972084"},
            content=b"oversized-body",
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(oversized_handler))
    with pytest.raises(SarvamTTSError, match="Sarvam TTS request failed"):
        await _request_clip(
            client,
            text="Some text",
            api_key="test-key",
            language="en-IN",
            speaker="shubh",
            max_audio_bytes=2_000_000,
        )
    await client.aclose()


@pytest.mark.asyncio
async def test_realistic_safe_sized_provider_response_succeeds():
    """Verify that a realistic safe-sized provider response (e.g. 1.2 MB audio) succeeds cleanly."""
    import json

    safe_audio = b"RIFF" + b"\x00" * 1_200_000
    encoded = base64.b64encode(safe_audio).decode("ascii")
    body = json.dumps({"audios": [encoded]}).encode("utf-8")

    async def safe_handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": str(len(body))},
            content=body,
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(safe_handler))
    clips = await synthesize(
        "A safe assistant response.",
        api_key="unit-test-key",
        language="en-IN",
        speaker="shubh",
        timeout_seconds=5,
        max_total_chars=1000,
        max_chunks=3,
        max_audio_bytes_per_clip=2_000_000,
        max_total_audio_bytes=4_000_000,
        client=client,
    )
    assert len(clips) == 1
    assert len(clips[0].audio_bytes) == len(safe_audio)
    await client.aclose()


def test_chunking_keeps_requests_within_safe_response_bounds():
    """Verify that for production clip limits (2MB), synthesized chunks are conservatively bounded (~320 chars)."""
    from backend.services.sarvam_tts import SARVAM_AUDIO_BYTES_PER_CHAR_RATIO, _max_encoded_response_bytes
    from backend.services.text_prep import prepare_for_speech

    max_clip_bytes = 2_000_000
    chunk_size = int(max_clip_bytes / SARVAM_AUDIO_BYTES_PER_CHAR_RATIO)  # 320 chars
    max_enc = _max_encoded_response_bytes(max_clip_bytes)  # 2,683,052 bytes

    text = "Security investigation notes. " * 30  # ~900 chars
    chunks = prepare_for_speech(
        text,
        max_total_chars=1000,
        max_chars_per_chunk=chunk_size,
        max_chunks=3,
    )
    assert len(chunks) <= 3
    for c in chunks:
        assert len(c) <= chunk_size
        # Even at worst-case audio density of 4,500 bytes/char, max expected audio <= 1.44 MB (< 2 MB)
        expected_worst_case_audio = len(c) * 4500
        assert expected_worst_case_audio < max_clip_bytes
        # Worst-case encoded response <= 1.94 MB (< 2.68 MB max_encoded_response_bytes)
        expected_worst_case_encoded = ((expected_worst_case_audio + 2) // 3) * 4 + 16384
        assert expected_worst_case_encoded < max_enc


