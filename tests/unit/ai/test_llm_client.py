import pytest
from unittest.mock import patch, AsyncMock, call
from ai.llm_client import call_llm, GeminiAdapter, OpenAIAdapter, _with_retry

pytestmark = pytest.mark.asyncio


# --- RETRY TESTS ---

@patch("ai.llm_client.asyncio.sleep", new_callable=AsyncMock)
async def test_retry_first_fails_second_succeeds(mock_sleep):
    mock_func = AsyncMock(side_effect=[Exception("transient network drop"), "Success Attempt 2"])

    result = await _with_retry(mock_func, max_retries=3, backoff_factor=1.0)

    assert result == "Success Attempt 2"
    assert mock_func.call_count == 2
    assert mock_sleep.call_count == 1
    mock_sleep.assert_called_once_with(1.0)  # backoff_factor * 2^0


@patch("ai.llm_client.asyncio.sleep", new_callable=AsyncMock)
async def test_retry_first_two_fail_third_succeeds_exponential_backoff(mock_sleep):
    mock_func = AsyncMock(side_effect=[
        Exception("503 Service Unavailable"),
        Exception("429 Too Many Requests"),
        "Success Attempt 3"
    ])

    result = await _with_retry(mock_func, max_retries=3, backoff_factor=2.0)

    assert result == "Success Attempt 3"
    assert mock_func.call_count == 3
    assert mock_sleep.call_count == 2
    # Verify exponential delays: 2.0 * 2^0 = 2.0, 2.0 * 2^1 = 4.0
    mock_sleep.assert_has_calls([call(2.0), call(4.0)])


@patch("ai.llm_client.asyncio.sleep", new_callable=AsyncMock)
async def test_retry_all_retries_fail(mock_sleep):
    mock_func = AsyncMock(side_effect=[
        Exception("fail 1"),
        Exception("fail 2"),
        Exception("fail 3"),
    ])

    with pytest.raises(Exception, match="fail 3"):
        await _with_retry(mock_func, max_retries=3, backoff_factor=1.0)

    assert mock_func.call_count == 3
    assert mock_sleep.call_count == 2


@patch("ai.llm_client.asyncio.sleep", new_callable=AsyncMock)
async def test_retry_permanent_auth_error_not_retried(mock_sleep):
    mock_func = AsyncMock(side_effect=ValueError("Invalid API key provided"))

    with pytest.raises(ValueError, match="Invalid API key provided"):
        await _with_retry(mock_func, max_retries=3)

    assert mock_func.call_count == 1
    mock_sleep.assert_not_called()


# --- PROVIDER SELECTION & FALLBACK TESTS ---

@patch("ai.llm_client.settings")
@patch.object(GeminiAdapter, "generate", new_callable=AsyncMock)
@patch.object(OpenAIAdapter, "generate", new_callable=AsyncMock)
async def test_primary_gemini_succeeds_secondary_never_called(mock_openai, mock_gemini, mock_settings):
    mock_settings.llm_provider = "gemini"
    mock_settings.gemini_api_key = "gemini-secret-key"
    mock_settings.openai_api_key = "openai-secret-key"
    mock_gemini.return_value = "Gemini Response"

    result = await call_llm("sys prompt", "user prompt")

    assert result == "Gemini Response"
    mock_gemini.assert_called_once_with("sys prompt", "user prompt")
    mock_openai.assert_not_called()


@patch("ai.llm_client.settings")
@patch.object(GeminiAdapter, "generate", new_callable=AsyncMock)
@patch.object(OpenAIAdapter, "generate", new_callable=AsyncMock)
@patch("ai.llm_client.asyncio.sleep", new_callable=AsyncMock)
async def test_primary_fails_after_retries_secondary_succeeds(mock_sleep, mock_openai, mock_gemini, mock_settings):
    mock_settings.llm_provider = "gemini"
    mock_settings.gemini_api_key = "gemini-key"
    mock_settings.openai_api_key = "openai-key"

    mock_gemini.side_effect = Exception("Gemini server error")
    mock_openai.return_value = "OpenAI Fallback Response"

    result = await call_llm("sys prompt", "user prompt")

    assert result == "OpenAI Fallback Response"
    assert mock_gemini.call_count == 3
    assert mock_openai.call_count == 1
    mock_openai.assert_called_once_with("sys prompt", "user prompt")


@patch("ai.llm_client.settings")
@patch.object(GeminiAdapter, "generate", new_callable=AsyncMock)
@patch.object(OpenAIAdapter, "generate", new_callable=AsyncMock)
@patch("ai.llm_client.asyncio.sleep", new_callable=AsyncMock)
async def test_both_providers_fail_raises_controlled_error(mock_sleep, mock_openai, mock_gemini, mock_settings):
    mock_settings.llm_provider = "gemini"
    mock_settings.gemini_api_key = "gemini-key"
    mock_settings.openai_api_key = "openai-key"

    mock_gemini.side_effect = Exception("Gemini dead")
    mock_openai.side_effect = Exception("OpenAI dead")

    with pytest.raises(Exception, match="OpenAI dead"):
        await call_llm("sys prompt", "user prompt")

    assert mock_gemini.call_count == 3
    assert mock_openai.call_count == 3


@patch("ai.llm_client.settings")
@patch.object(GeminiAdapter, "generate", new_callable=AsyncMock)
@patch.object(OpenAIAdapter, "generate", new_callable=AsyncMock)
async def test_primary_openai_succeeds(mock_openai, mock_gemini, mock_settings):
    mock_settings.llm_provider = "openai"
    mock_settings.openai_api_key = "openai-key"
    mock_openai.return_value = "OpenAI direct response"

    result = await call_llm("sys prompt", "user prompt")

    assert result == "OpenAI direct response"
    mock_openai.assert_called_once_with("sys prompt", "user prompt")
    mock_gemini.assert_not_called()
