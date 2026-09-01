from __future__ import annotations

import asyncio
import logging
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, AsyncIterator, Callable

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.config import get_settings


class _SettingsProxy:
    """Proxy that dynamically delegates attribute access to get_settings().

    Ensures that runtime configuration updates and test environment overrides
    (e.g. via monkeypatch.setenv and get_settings.cache_clear()) are immediately
    reflected without holding onto stale module-level references, while preserving
    compatibility with @patch("ai.llm_client.settings").
    """

    def __getattr__(self, name: str) -> Any:
        return getattr(get_settings(), name)

    def __repr__(self) -> str:
        return repr(get_settings())


settings = _SettingsProxy()
logger = logging.getLogger("soc.ai")


class BaseLLMClient(ABC):
    @abstractmethod
    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate response from the LLM."""
        pass

    @abstractmethod
    async def generate_stream(self, system_prompt: str, user_prompt: str) -> AsyncIterator[str]:
        """Stream response chunks from the LLM."""
        pass


class GeminiAdapter(BaseLLMClient):
    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        from google import genai
        from google.genai import types

        if not settings.gemini_api_key:
            raise ValueError("Gemini API key is not configured")

        client = genai.Client(api_key=settings.gemini_api_key)

        try:
            response = await client.aio.models.generate_content(
                model=settings.gemini_model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=0.2,
                    max_output_tokens=3000,
                ),
            )
        except Exception as e:
            err_str = str(e).lower()
            if "api key not valid" in err_str or "401" in err_str or "403" in err_str:
                raise ValueError("Gemini authentication failed") from e
            raise

        if not response.text:
            raise RuntimeError("Gemini returned an empty response")

        return response.text

    async def generate_stream(self, system_prompt: str, user_prompt: str) -> AsyncIterator[str]:
        from google import genai
        from google.genai import types

        if not settings.gemini_api_key:
            raise ValueError("Gemini API key is not configured")

        client = genai.Client(api_key=settings.gemini_api_key)

        try:
            response = await client.aio.models.generate_content_stream(
                model=settings.gemini_model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=0.2,
                    max_output_tokens=3000,
                ),
            )
            async for chunk in response:
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            err_str = str(e).lower()
            if "api key not valid" in err_str or "401" in err_str or "403" in err_str:
                raise ValueError("Gemini authentication failed") from e
            raise


class OpenAIAdapter(BaseLLMClient):
    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        from openai import AsyncOpenAI, AuthenticationError

        if not settings.openai_api_key:
            raise ValueError("OpenAI API key is not configured")

        client = AsyncOpenAI(api_key=settings.openai_api_key)

        try:
            response = await client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                max_tokens=1500,
            )
        except AuthenticationError as e:
            raise ValueError("OpenAI authentication failed") from e

        return response.choices[0].message.content or ""

    async def generate_stream(self, system_prompt: str, user_prompt: str) -> AsyncIterator[str]:
        from openai import AsyncOpenAI, AuthenticationError

        if not settings.openai_api_key:
            raise ValueError("OpenAI API key is not configured")

        client = AsyncOpenAI(api_key=settings.openai_api_key)

        try:
            response = await client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                max_tokens=1500,
                stream=True,
            )
            async for chunk in response:
                if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except AuthenticationError as e:
            raise ValueError("OpenAI authentication failed") from e


async def _with_retry(
    func: Callable[[], Any],
    max_retries: int = 3,
    backoff_factor: float = 2.0,
) -> str:
    """Execute a function with exponential backoff for transient errors."""
    attempt = 0
    while attempt < max_retries:
        try:
            return await func()
        except ValueError:
            # Permanent errors (e.g. invalid configuration or credentials)
            raise
        except Exception as e:
            attempt += 1
            if attempt >= max_retries:
                logger.warning("LLM request failed after %d attempts.", max_retries)
                raise

            delay = backoff_factor * (2 ** (attempt - 1))
            logger.debug("LLM request transient failure, retrying in %s seconds...", delay)
            await asyncio.sleep(delay)

    raise RuntimeError("Unexpected retry loop exit")


_llm_semaphore: Optional[asyncio.Semaphore] = None


def get_llm_semaphore() -> asyncio.Semaphore:
    """Return the process-wide LLM concurrency semaphore."""
    global _llm_semaphore
    if _llm_semaphore is None:
        curr_settings = get_settings()
        _llm_semaphore = asyncio.Semaphore(curr_settings.max_concurrent_llm_requests)
    return _llm_semaphore


def reset_llm_semaphore() -> None:
    """Reset the LLM semaphore (used in tests)."""
    global _llm_semaphore
    _llm_semaphore = None


async def call_llm(system_prompt: str, user_prompt: str) -> str:
    """Generate LLM response with exponential backoff, provider fallback, and bounded concurrency."""
    sem = get_llm_semaphore()
    async with sem:
        provider = settings.llm_provider.lower()

        async def _run_gemini() -> str:
            adapter = GeminiAdapter()
            return await _with_retry(lambda: adapter.generate(system_prompt, user_prompt))

        async def _run_openai() -> str:
            adapter = OpenAIAdapter()
            return await _with_retry(lambda: adapter.generate(system_prompt, user_prompt))

        if provider == "gemini":
            try:
                return await _run_gemini()
            except Exception as e:
                logger.warning("Gemini primary provider failed, falling back to OpenAI.")
                if settings.openai_api_key:
                    return await _run_openai()
                raise

        try:
            return await _run_openai()
        except Exception as e:
            logger.warning("OpenAI primary provider failed, falling back to Gemini.")
            if settings.gemini_api_key:
                return await _run_gemini()
            raise


async def _stream_with_pretoken_retry(
    adapter: BaseLLMClient,
    system_prompt: str,
    user_prompt: str,
    max_retries: int = 3,
    backoff_factor: float = 2.0,
) -> AsyncIterator[str]:
    """Stream from an adapter with retries for transient errors before the first token.

    If an error occurs after the first token is emitted, it is raised immediately
    without retrying or restarting the stream.
    """
    attempt = 0
    while attempt < max_retries:
        has_yielded = False
        try:
            stream = adapter.generate_stream(system_prompt, user_prompt)
            async for token in stream:
                has_yielded = True
                yield token
            return
        except ValueError:
            # Permanent error (e.g. invalid config or credentials)
            raise
        except Exception as e:
            if has_yielded:
                # Streaming failed mid-stream after emitting tokens; do NOT retry from start
                logger.error("LLM streaming failed mid-stream after emitting tokens: %s", e)
                raise
            attempt += 1
            if attempt >= max_retries:
                logger.warning("LLM streaming request failed before first token after %d attempts: %s", max_retries, e)
                raise
            delay = backoff_factor * (2 ** (attempt - 1))
            logger.debug("LLM stream transient failure before first token, retrying in %s seconds...", delay)
            await asyncio.sleep(delay)

    raise RuntimeError("Unexpected stream retry loop exit")


async def call_llm_stream(system_prompt: str, user_prompt: str) -> AsyncIterator[str]:
    """Stream responses from the configured LLM provider with safe pre-first-token fallback and concurrency bounds."""
    sem = get_llm_semaphore()
    await sem.acquire()
    try:
        provider = settings.llm_provider.lower()

        async def _try_stream(primary: BaseLLMClient, secondary: Optional[BaseLLMClient]) -> AsyncIterator[str]:
            has_yielded = False
            try:
                async for token in _stream_with_pretoken_retry(primary, system_prompt, user_prompt):
                    has_yielded = True
                    yield token
                return
            except Exception as primary_exc:
                if has_yielded:
                    # Streaming already started and emitted tokens; DO NOT switch to secondary
                    raise
                if secondary is not None:
                    logger.warning(
                        "Primary provider stream failed before first token; falling back to secondary provider. Error: %s",
                        primary_exc,
                    )
                    async for token in _stream_with_pretoken_retry(secondary, system_prompt, user_prompt):
                        yield token
                    return
                raise

        if provider == "gemini":
            primary = GeminiAdapter()
            secondary = OpenAIAdapter() if settings.openai_api_key else None
            async for token in _try_stream(primary, secondary):
                yield token
            return

        primary = OpenAIAdapter()
        secondary = GeminiAdapter() if settings.gemini_api_key else None
        async for token in _try_stream(primary, secondary):
            yield token
    finally:
        sem.release()
