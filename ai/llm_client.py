"""
LLM Client — thin wrapper for Gemini 1.5 Flash (primary) and GPT-4o-mini (fallback).
Configured via LLM_PROVIDER env variable.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.config import get_settings

settings = get_settings()


async def call_llm(system_prompt: str, user_prompt: str) -> str:
    """
    Call the configured LLM and return the text response.

    Tries Gemini first if LLM_PROVIDER=gemini, else OpenAI.
    Falls back to the other provider on error.
    """
    if settings.llm_provider.lower() == "gemini":
        try:
            return await _call_gemini(system_prompt, user_prompt)
        except Exception as e:
            print(f"[LLM] Gemini failed ({e}), falling back to OpenAI...")
            return await _call_openai(system_prompt, user_prompt)
    else:
        try:
            return await _call_openai(system_prompt, user_prompt)
        except Exception as e:
            print(f"[LLM] OpenAI failed ({e}), falling back to Gemini...")
            return await _call_gemini(system_prompt, user_prompt)


async def _call_gemini(system_prompt: str, user_prompt: str) -> str:
    """Call Google Gemini 1.5 Flash."""
    import google.generativeai as genai

    genai.configure(api_key=settings.gemini_api_key)
    model = genai.GenerativeModel(
        model_name=settings.gemini_model,
        system_instruction=system_prompt,
    )
    response = model.generate_content(user_prompt)
    return response.text


async def _call_openai(system_prompt: str, user_prompt: str) -> str:
    """Call OpenAI GPT-4o-mini."""
    from openai import AsyncOpenAI

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
