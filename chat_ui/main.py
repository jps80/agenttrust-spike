"""
chat_ui/main.py

Interfaz web para interactuar con Agent1 (Translator).

Expone:
  GET  /          → página de chat
  POST /ask       → proxy a Agent1 POST /ask (devuelve JSON para AJAX)
  GET  /health

Uso:
  uvicorn chat_ui.main:app --port 8003 --reload
  o: make run-chat
"""
from __future__ import annotations

import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

load_dotenv()

AGENT1_BASE_URL = os.getenv("AGENT1_BASE_URL", "http://localhost:8011")

app = FastAPI(title="AgentTrust Chat UI")

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "agent1_url": AGENT1_BASE_URL},
    )


class AskRequest(BaseModel):
    question: str


@app.post("/ask")
async def ask(req: AskRequest):
    if not req.question.strip():
        return JSONResponse({"error": "La pregunta no puede estar vacía"}, status_code=400)

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{AGENT1_BASE_URL}/ask",
                json={"question": req.question.strip()},
            )
            if resp.status_code == 403:
                data = resp.json()
                return JSONResponse(
                    {"error": f"Mandato denegado: {data.get('detail', 'acceso denegado')}"},
                    status_code=403,
                )
            resp.raise_for_status()
            return JSONResponse(resp.json())
    except httpx.ConnectError:
        return JSONResponse(
            {"error": f"Agent1 no responde en {AGENT1_BASE_URL}. ¿Está arrancado? Ejecuta: make start-agents"},
            status_code=503,
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)
