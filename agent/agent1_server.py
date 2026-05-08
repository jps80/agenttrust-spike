"""
agent/agent1_server.py

Servidor HTTP de Agent1 (Translator).

Expone un único endpoint:
  POST /ask   { "question": "¿...?" }
              → { "question_es", "question_en", "answer_en", "answer_es" }

Flujo interno:
  1. Recibe la pregunta en español.
  2. Traduce ES → EN con Claude.
  3. Presenta su mandato a Agent2 (PeerClient) para solicitar execute:answer_question.
     Agent2 verifica la cadena completa (VP JWT, holder binding, revocación, scope).
  4. Agent2 responde con la respuesta en inglés (generada con Claude).
  5. Traduce la respuesta EN → ES con Claude.
  6. Devuelve el objeto completo al usuario.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

load_dotenv()

from shared.claude_client import translate

AGENT1_BASE_URL = os.getenv("AGENT1_BASE_URL", "http://localhost:8011")
AGENT2_URL = os.getenv("AGENT2_BASE_URL", "http://localhost:8010")

# Holder and PeerClient are injected at startup by start_ai_agents.py
_holder = None
_peer_client = None


def init_agent1(holder, peer_client) -> None:
    """Inyecta el AgentHolder y PeerClient antes de arrancar."""
    global _holder, _peer_client
    _holder = holder
    _peer_client = peer_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    if _holder is None:
        raise RuntimeError("Llama a init_agent1(holder, peer_client) antes de arrancar")
    print(f"[AGENT1:SERVER] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", flush=True)
    print(f"[AGENT1:SERVER] Servidor Translator arrancado en {AGENT1_BASE_URL}", flush=True)
    print(f"[AGENT1:SERVER]   DID de este agente : {_holder.did}", flush=True)
    print(f"[AGENT1:SERVER]   Peer (Agent2) URL  : {AGENT2_URL}", flush=True)
    print(f"[AGENT1:SERVER] Listo para recibir preguntas en /ask", flush=True)
    print(f"[AGENT1:SERVER] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", flush=True)
    yield


app = FastAPI(title="AgentTrust Agent1 — Translator", lifespan=lifespan)


class AskRequest(BaseModel):
    question: str


class AskResponse(BaseModel):
    question_es: str
    question_en: str
    answer_en: str
    answer_es: str


@app.get("/health")
def health():
    return {
        "status": "ok",
        "agent": "translator",
        "agent_did": _holder.did if _holder else "not-initialized",
        "has_credential": (_holder.credential is not None) if _holder else False,
    }


@app.post("/ask", response_model=AskResponse)
def ask(req: AskRequest):
    """
    Recibe una pregunta en español y devuelve la respuesta también en español,
    pasando por Agent2 para que responda con IA.
    """
    if _holder is None or _peer_client is None:
        raise HTTPException(status_code=503, detail="Agente no inicializado")

    question_es = req.question.strip()
    if not question_es:
        raise HTTPException(status_code=400, detail="La pregunta no puede estar vacía")

    print(f"\n[AGENT1:ASK] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", flush=True)
    print(f"[AGENT1:ASK] Nueva pregunta recibida: {question_es}", flush=True)

    # Paso 1 — Traducir pregunta ES → EN
    print(f"[AGENT1:ASK] [1/3] Traduciendo pregunta ES → EN…", flush=True)
    question_en = translate(question_es, from_lang="Spanish", to_lang="English")
    print(f"[AGENT1:ASK]   Pregunta en inglés: {question_en}", flush=True)

    # Paso 2 — Presentar mandato a Agent2 y solicitar respuesta
    print(f"[AGENT1:ASK] [2/3] Solicitando respuesta a Agent2 (execute:answer_question)…", flush=True)
    result = _peer_client.request_action(
        action="execute:answer_question",
        params={"question": question_en},
        context="qa-service",
        environment="prod",
    )

    if not result.get("authorized"):
        reason = result.get("reason", "mandato denegado")
        print(f"[AGENT1:ASK] ❌ Agent2 denegó la acción: {reason}", flush=True)
        raise HTTPException(status_code=403, detail=f"Agent2 denegó la solicitud: {reason}")

    answer_en = result.get("result", {}).get("answer", "")
    if not answer_en:
        raise HTTPException(status_code=502, detail="Agent2 no devolvió respuesta")

    print(f"[AGENT1:ASK]   Respuesta en inglés: {answer_en[:120]}…", flush=True)

    # Paso 3 — Traducir respuesta EN → ES
    print(f"[AGENT1:ASK] [3/3] Traduciendo respuesta EN → ES…", flush=True)
    answer_es = translate(answer_en, from_lang="English", to_lang="Spanish")
    print(f"[AGENT1:ASK]   Respuesta en español: {answer_es[:120]}…", flush=True)
    print(f"[AGENT1:ASK] ✅ Ciclo completo. Devolviendo al usuario.", flush=True)
    print(f"[AGENT1:ASK] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", flush=True)

    return AskResponse(
        question_es=question_es,
        question_en=question_en,
        answer_en=answer_en,
        answer_es=answer_es,
    )
