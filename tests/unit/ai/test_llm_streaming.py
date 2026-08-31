import pytest
from unittest.mock import AsyncMock, patch, call

from ai.llm_client import GeminiAdapter, OpenAIAdapter, call_llm_stream

pytestmark = pytest.mark.asyncio


async def _async_iter(items):
    for item in items:
        yield item


@patch("ai.llm_client.settings")
async def test_call_llm_stream_gemini_success(mock_settings):
    mock_settings.llm_provider = "gemini"
    mock_settings.gemini_api_key = "gemini-key"

    with patch.object(GeminiAdapter, "generate_stream") as mock_stream:
        mock_stream.return_value = _async_iter(["Chunk 1 ", "Chunk 2 ", "Chunk 3"])

        chunks = []
        async for chunk in call_llm_stream("sys", "user"):
            chunks.append(chunk)

        assert "".join(chunks) == "Chunk 1 Chunk 2 Chunk 3"
        mock_stream.assert_called_once_with("sys", "user")


@patch("ai.llm_client.settings")
async def test_call_llm_stream_openai_success(mock_settings):
    mock_settings.llm_provider = "openai"
    mock_settings.openai_api_key = "openai-key"

    with patch.object(OpenAIAdapter, "generate_stream") as mock_stream:
        mock_stream.return_value = _async_iter(["OpenAI token 1", " token 2"])

        chunks = []
        async for chunk in call_llm_stream("sys", "user"):
            chunks.append(chunk)

        assert "".join(chunks) == "OpenAI token 1 token 2"
        mock_stream.assert_called_once_with("sys", "user")


@patch("ai.llm_client.settings")
@patch("ai.llm_client.asyncio.sleep", new_callable=AsyncMock)
async def test_call_llm_stream_primary_fails_before_first_token_fallback(mock_sleep, mock_settings):
    mock_settings.llm_provider = "gemini"
    mock_settings.gemini_api_key = "gemini-key"
    mock_settings.openai_api_key = "openai-key"

    async def _failing_stream(sys, user):
        raise RuntimeError("Gemini pre-token error")
        yield "never"

    with patch.object(GeminiAdapter, "generate_stream", side_effect=_failing_stream) as mock_gemini, \
         patch.object(OpenAIAdapter, "generate_stream") as mock_openai:

        mock_openai.return_value = _async_iter(["OpenAI ", "Fallback ", "Tokens"])

        chunks = []
        async for chunk in call_llm_stream("sys", "user"):
            chunks.append(chunk)

        assert "".join(chunks) == "OpenAI Fallback Tokens"
        assert mock_gemini.call_count == 3  # Tried retries before first token
        mock_openai.assert_called_once_with("sys", "user")


@patch("ai.llm_client.settings")
async def test_call_llm_stream_primary_fails_after_first_token_no_fallback(mock_settings):
    """If primary emitted tokens and then dies, secondary MUST NOT be called."""
    mock_settings.llm_provider = "gemini"
    mock_settings.gemini_api_key = "gemini-key"
    mock_settings.openai_api_key = "openai-key"

    async def _partial_stream(sys, user):
        yield "The incident started with"
        yield " a brute-force attempt"
        raise RuntimeError("Mid-stream connection drop!")

    with patch.object(GeminiAdapter, "generate_stream", side_effect=_partial_stream), \
         patch.object(OpenAIAdapter, "generate_stream") as mock_openai:

        chunks = []
        with pytest.raises(RuntimeError, match="Mid-stream connection drop!"):
            async for chunk in call_llm_stream("sys", "user"):
                chunks.append(chunk)

        # Emitted partial tokens before error
        assert "".join(chunks) == "The incident started with a brute-force attempt"
        # Secondary provider MUST NOT have been called
        mock_openai.assert_not_called()


@patch("ai.llm_client.settings")
@patch("ai.llm_client.asyncio.sleep", new_callable=AsyncMock)
async def test_call_llm_stream_pretoken_retry_transient_success(mock_sleep, mock_settings):
    """Transient failure before first token is retried with backoff and succeeds on attempt 2."""
    mock_settings.llm_provider = "gemini"
    mock_settings.gemini_api_key = "gemini-key"

    call_count = 0

    async def _flaky_stream(sys, user):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("503 Service Unavailable")
            yield "never"
        yield "Success Token 1"
        yield " Success Token 2"

    with patch.object(GeminiAdapter, "generate_stream", side_effect=_flaky_stream), \
         patch.object(OpenAIAdapter, "generate_stream") as mock_openai:

        chunks = []
        async for chunk in call_llm_stream("sys", "user"):
            chunks.append(chunk)

        assert "".join(chunks) == "Success Token 1 Success Token 2"
        assert call_count == 2
        mock_sleep.assert_called_once_with(2.0)
        mock_openai.assert_not_called()


@patch("ai.llm_client.settings")
@patch("ai.llm_client.asyncio.sleep", new_callable=AsyncMock)
async def test_call_llm_stream_permanent_auth_error_no_retries(mock_sleep, mock_settings):
    """Permanent error (ValueError) does not get retried 3 times before fallback."""
    mock_settings.llm_provider = "gemini"
    mock_settings.gemini_api_key = "gemini-key"
    mock_settings.openai_api_key = "openai-key"

    with patch.object(GeminiAdapter, "generate_stream", side_effect=ValueError("Invalid Gemini Key")) as mock_gemini, \
         patch.object(OpenAIAdapter, "generate_stream") as mock_openai:

        mock_openai.return_value = _async_iter(["OpenAI ", "Response"])

        chunks = []
        async for chunk in call_llm_stream("sys", "user"):
            chunks.append(chunk)

        assert "".join(chunks) == "OpenAI Response"
        assert mock_gemini.call_count == 1  # No pointless retries
        mock_sleep.assert_not_called()
        mock_openai.assert_called_once_with("sys", "user")


@patch("ai.llm_client.settings")
@patch("ai.llm_client.asyncio.sleep", new_callable=AsyncMock)
async def test_call_llm_stream_both_providers_fail_before_first_token(mock_sleep, mock_settings):
    mock_settings.llm_provider = "gemini"
    mock_settings.gemini_api_key = "gemini-key"
    mock_settings.openai_api_key = "openai-key"

    async def _gemini_fail(sys, user):
        raise RuntimeError("Gemini dead")
        yield "never"

    async def _openai_fail(sys, user):
        raise RuntimeError("OpenAI dead")
        yield "never"

    with patch.object(GeminiAdapter, "generate_stream", side_effect=_gemini_fail), \
         patch.object(OpenAIAdapter, "generate_stream", side_effect=_openai_fail):

        with pytest.raises(RuntimeError, match="OpenAI dead"):
            async for _ in call_llm_stream("sys", "user"):
                pass
