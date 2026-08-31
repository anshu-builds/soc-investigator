from __future__ import annotations

import asyncio
import logging
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.config import get_settings

settings = get_settings()
logger = logging.getLogger("soc.ai")


class BaseLLMClient(ABC):
    @abstractmethod
    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate response from the LLM."""
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


async def call_llm(system_prompt: str, user_prompt: str) -> str:
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
