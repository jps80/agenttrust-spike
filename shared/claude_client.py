"""
shared/claude_client.py

Thin wrapper around the Anthropic SDK for the two AI capabilities used
in this spike: translation (ES ↔ EN) and Q&A answering.

Requires ANTHROPIC_API_KEY to be set (via .env or environment).
"""
from __future__ import annotations

import os

import anthropic

_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY no está configurada. "
                "Añádela a .env o como variable de entorno."
            )
        _client = anthropic.Anthropic(api_key=api_key)
    return _client


_MODEL = "claude-opus-4-7"


def translate(text: str, from_lang: str, to_lang: str) -> str:
    """
    Translate `text` from `from_lang` to `to_lang`.
    Returns only the translated text (no explanations).
    """
    client = _get_client()
    print(f"[CLAUDE:TRANSLATE] {from_lang} → {to_lang} | texto: {text[:80]}…", flush=True)

    message = client.messages.create(
        model=_MODEL,
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Translate the following text from {from_lang} to {to_lang}. "
                    "Return only the translated text, no explanations, no quotes.\n\n"
                    f"{text}"
                ),
            }
        ],
    )
    result = message.content[0].text.strip()
    print(f"[CLAUDE:TRANSLATE] resultado: {result[:80]}…", flush=True)
    return result


def answer(question: str) -> str:
    """
    Answer `question` in English. Returns a concise, direct answer.
    """
    client = _get_client()
    print(f"[CLAUDE:ANSWER] pregunta: {question[:80]}…", flush=True)

    message = client.messages.create(
        model=_MODEL,
        max_tokens=2048,
        thinking={"type": "adaptive"},
        messages=[
            {
                "role": "user",
                "content": (
                    "You are a knowledgeable expert assistant. "
                    "Answer the following question clearly and concisely in English.\n\n"
                    f"{question}"
                ),
            }
        ],
    )
    # Collect text blocks (thinking blocks have no visible text)
    result = "".join(
        block.text for block in message.content if block.type == "text"
    ).strip()
    print(f"[CLAUDE:ANSWER] respuesta: {result[:80]}…", flush=True)
    return result
