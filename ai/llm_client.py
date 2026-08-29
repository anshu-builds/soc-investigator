from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.config import get_settings

settings = get_settings()


async def call_llm(system_prompt: str, user_prompt: str) -> str:
    provider = settings.llm_provider.lower()

    if provider == "gemini":
        try:
            return await _call_gemini(system_prompt, user_prompt)
        except Exception as e:
            print(f"[LLM] Gemini failed: {e}")

            if settings.openai_api_key:
                print("[LLM] Falling back to OpenAI...")
                return await _call_openai(system_prompt, user_prompt)

            raise

    try:
        return await _call_openai(system_prompt, user_prompt)
    except Exception as e:
        print(f"[LLM] OpenAI failed: {e}")

        if settings.gemini_api_key:
            print("[LLM] Falling back to Gemini...")
            return await _call_gemini(system_prompt, user_prompt)

        raise


async def _call_gemini(system_prompt: str, user_prompt: str) -> str:
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=settings.gemini_api_key)

    response = await client.aio.models.generate_content(
        model=settings.gemini_model,
        contents=user_prompt,
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.2,
            max_output_tokens=3000,
        ),
    )

    if not response.text:
        raise RuntimeError("Gemini returned an empty response")

    return response.text


async def _call_openai(system_prompt: str, user_prompt: str) -> str:
    from openai import AsyncOpenAI

    if not settings.openai_api_key:
        raise RuntimeError("OpenAI API key is not configured")

    client = AsyncOpenAI(api_key=settings.openai_api_key)

    response = await client.chat.completions.create(
        model=settings.openai_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
        max_tokens=1500,
    )

    return response.choices[0].message.content or ""
