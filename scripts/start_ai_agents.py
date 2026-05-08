#!/usr/bin/env python3
"""
scripts/start_ai_agents.py

Arranca los dos agentes IA del spike AgentTrust:
  - Agent2 (Expert / Infra Operator) en el puerto 8010 — responde preguntas en inglés
  - Agent1 (Translator)             en el puerto 8011 — traduce ES→EN y EN→ES

Prerrequisitos:
  - issuer       corriendo en http://localhost:8000
  - verifier     corriendo en http://localhost:8001
  - registry_ui  corriendo en http://localhost:8002
  - ANTHROPIC_API_KEY en .env o en el entorno

Uso:
  python scripts/start_ai_agents.py

Después, desde otra terminal:
  curl -X POST http://localhost:8011/ask \\
       -H 'Content-Type: application/json' \\
       -d '{"question": "¿Cuál es la capital de Francia?"}'
"""
from __future__ import annotations

import base64
import json as _json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Thread

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
import uvicorn
from dotenv import load_dotenv

load_dotenv()

from shared import build_custody
from agent.holder import AgentHolder
from agent.peer_client import PeerClient
from agent.peer_server import app as peer_app, init_server
from agent.agent1_server import app as agent1_app, init_agent1

ISSUER   = os.getenv("ISSUER_BASE_URL",      "http://localhost:8000")
VERIFIER = os.getenv("VERIFIER_BASE_URL",    "http://localhost:8001")
REGISTRY = os.getenv("REGISTRY_UI_BASE_URL", "http://localhost:8002")
AGENT2_URL = os.getenv("AGENT2_BASE_URL",    "http://localhost:8010")
AGENT1_URL = os.getenv("AGENT1_BASE_URL",    "http://localhost:8011")

AGENT1_ID = "translator-001"
AGENT2_ID = "expert-001"


# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────

def banner(title: str) -> None:
    print(); print("=" * 72); print(f"  {title}"); print("=" * 72)

def step(msg: str) -> None:
    print(f"\n→ {msg}")

def ok(msg: str) -> None:
    print(f"  ✓ {msg}")

def warn(msg: str) -> None:
    print(f"  ✗ {msg}")

def info(label: str, value) -> None:
    print(f"    {label:<28} {value}")

def _decode_jwt_payload(jwt_str: str) -> dict:
    part = jwt_str.split(".")[1]
    part += "=" * (-len(part) % 4)
    return _json.loads(base64.urlsafe_b64decode(part))


# ─────────────────────────────────────────────────────────────────────────────
# check base services
# ─────────────────────────────────────────────────────────────────────────────

def check_services() -> None:
    step("Comprobando servicios base")
    for name, url in [("issuer", ISSUER), ("verifier", VERIFIER), ("registry_ui", REGISTRY)]:
        try:
            httpx.get(f"{url}/health", timeout=3.0).raise_for_status()
            ok(f"{name} → {url}")
        except Exception as e:
            warn(f"{name} en {url} no responde: {e}")
            print("\n  Arranca los servicios base antes de ejecutar este script:")
            print("    make run-issuer    # :8000")
            print("    make run-verifier  # :8001")
            print("    make run-registry  # :8002")
            sys.exit(2)


# ─────────────────────────────────────────────────────────────────────────────
# register + credential fetch
# ─────────────────────────────────────────────────────────────────────────────

def register_agent(agent_id: str, scope: list[str], context: str) -> dict:
    valid_from  = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    valid_until = (datetime.now(tz=timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "agent_id": agent_id,
        "delegator_did": f"{os.getenv('ORG_DID', 'did:web:localhost%3A8000')}#supervisor-001",
        "scope": scope,
        "context": context,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "allowed_environments": ["prod", "staging"],
        "max_operations_per_hour": 200,
        "read_only": False,
    }
    r = httpx.post(f"{REGISTRY}/api/agents", json=payload, timeout=15.0)
    r.raise_for_status()
    return r.json()


def fetch_credential(agent_id: str, registration: dict) -> AgentHolder:
    custody = build_custody(f"agent-{agent_id}")
    holder  = AgentHolder(custody)
    offer   = httpx.get(registration["credential_offer_uri"], timeout=10.0).raise_for_status().json()
    holder.fetch_credential(credential_offer=offer)

    cred_path = f"./data/agents/{agent_id}.vc.json"
    holder.save_credential(cred_path)

    payload  = _decode_jwt_payload(holder.credential.vc_jwt)
    vc_inner = payload.get("vc", {})
    cs       = vc_inner.get("credentialSubject", {})
    mandate  = cs.get("mandate", {})
    info("  DID del agente", holder.did)
    info("  scope autorizado", mandate.get("scope", []))
    return holder


# ─────────────────────────────────────────────────────────────────────────────
# start Agent2 peer server in background thread
# ─────────────────────────────────────────────────────────────────────────────

def start_agent2(holder2: AgentHolder) -> None:
    init_server(holder2)
    config = uvicorn.Config(peer_app, host="0.0.0.0", port=8010, log_level="warning")
    server = uvicorn.Server(config)
    t = Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(20):
        try:
            httpx.get(f"{AGENT2_URL}/peer/health", timeout=1.0).raise_for_status()
            ok(f"Agent2 peer server listo en {AGENT2_URL}")
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("El peer server de Agent2 no arrancó a tiempo")


# ─────────────────────────────────────────────────────────────────────────────
# start Agent1 HTTP server in background thread
# ─────────────────────────────────────────────────────────────────────────────

def start_agent1(holder1: AgentHolder, peer_client: PeerClient) -> None:
    init_agent1(holder1, peer_client)
    config = uvicorn.Config(agent1_app, host="0.0.0.0", port=8011, log_level="warning")
    server = uvicorn.Server(config)
    t = Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(20):
        try:
            httpx.get(f"{AGENT1_URL}/health", timeout=1.0).raise_for_status()
            ok(f"Agent1 Translator listo en {AGENT1_URL}")
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("El servidor de Agent1 no arrancó a tiempo")


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    banner("AgentTrust — Arranque de Agentes IA (Translator + Expert)")
    info("issuer",      ISSUER)
    info("verifier",    VERIFIER)
    info("registry_ui", REGISTRY)
    info("agent2_url",  AGENT2_URL)
    info("agent1_url",  AGENT1_URL)
    info("custody",     os.getenv("KEY_CUSTODY_BACKEND", "local"))

    check_services()

    # ── Registro de agentes ───────────────────────────────────────────────────
    banner("Registrando agentes en la organización")

    step(f"Registrando Agent1 (Translator) con ID '{AGENT1_ID}'")
    reg1 = register_agent(
        AGENT1_ID,
        scope=["execute:translate", "execute:answer_question"],
        context="qa-service",
    )
    ok("Agent1 registrado")
    info("offer_uri", reg1["credential_offer_uri"])

    step(f"Registrando Agent2 (Expert) con ID '{AGENT2_ID}'")
    reg2 = register_agent(
        AGENT2_ID,
        scope=["execute:answer_question"],
        context="qa-service",
    )
    ok("Agent2 registrado")
    info("offer_uri", reg2["credential_offer_uri"])

    # ── Obtención de credenciales (OID4VCI) ───────────────────────────────────
    banner("Obteniendo Mandate Credentials (OID4VCI)")

    step(f"Agent1 ({AGENT1_ID}) — OID4VCI…")
    holder1 = fetch_credential(AGENT1_ID, reg1)
    ok("Agent1 tiene su Mandate Credential")

    step(f"Agent2 ({AGENT2_ID}) — OID4VCI…")
    holder2 = fetch_credential(AGENT2_ID, reg2)
    ok("Agent2 tiene su Mandate Credential")

    # ── Arrancar servidores ───────────────────────────────────────────────────
    banner("Arrancando servidores de los agentes")

    step("Arrancando Agent2 peer server (puerto 8010)…")
    start_agent2(holder2)

    step("Arrancando Agent1 Translator (puerto 8011)…")
    peer_client = PeerClient(holder1, AGENT2_URL)
    start_agent1(holder1, peer_client)

    # ── Listo ─────────────────────────────────────────────────────────────────
    banner("¡Agentes listos!")
    print("""
  Los dos agentes IA están en marcha:

    Agent1 (Translator) → http://localhost:8011/ask
    Agent2 (Expert)     → http://localhost:8010/peer/health

  Prueba con curl:

    curl -s -X POST http://localhost:8011/ask \\
         -H 'Content-Type: application/json' \\
         -d '{"question": "¿Cuál es la capital de Francia?"}' | python3 -m json.tool

  Pulsa Ctrl+C para detener.
    """)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Deteniendo agentes…")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
