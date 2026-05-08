#!/usr/bin/env python3
"""
scripts/demo_a2a.py

Demo Agent-to-Agent (A2A) del spike AgentTrust.

Escenario:
  - Agent1 es el "Incident Manager": detecta un incidente y necesita que
    Agent2 haga un backup de la base de datos como parte de la remediación.
  - Agent2 es el "Infra Operator": solo ejecuta acciones para agentes
    que puedan demostrar tener mandato para pedírselas.

Flujo:
  [PASO 0] La organización registra ambos agentes y emite sus Mandate Credentials.
  [PASO 1] Ambos agentes obtienen su credencial vía OID4VCI (H1).
  [PASO 2] Identificación mutua: Agent1 y Agent2 verifican la VC del otro.
  [PASO 3] Agent1 solicita a Agent2 ejecutar 'execute:database_backup'
           presentando su mandato vía VP JWT (A2A OID4VP-like).
           Agent2 verifica la cadena completa y ejecuta.
  [PASO 4] Agent1 intenta una acción que NO tiene en su mandato → DENEGADO.
  [PASO 5] La organización revoca el mandato de Agent1. La siguiente
           solicitud es rechazada aunque el mandato parecía válido.

Prerrequisitos:
  - issuer       corriendo en http://localhost:8000
  - verifier     corriendo en http://localhost:8001
  - registry_ui  corriendo en http://localhost:8002
  - Agent2 peer server corriendo en http://localhost:8010
    (inicia con: python scripts/start_agent2.py)
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
from dotenv import load_dotenv

load_dotenv()

from shared import build_custody  # noqa: E402
from agent.holder import AgentHolder  # noqa: E402
from agent.peer_client import PeerClient  # noqa: E402
from agent.peer_server import app as peer_app, init_server  # noqa: E402

ISSUER   = os.getenv("ISSUER_BASE_URL",       "http://localhost:8000")
VERIFIER = os.getenv("VERIFIER_BASE_URL",     "http://localhost:8001")
REGISTRY = os.getenv("REGISTRY_UI_BASE_URL",  "http://localhost:8002")
AGENT2_URL = os.getenv("AGENT2_BASE_URL",     "http://localhost:8010")

AGENT1_ID = "incident-manager-001"
AGENT2_ID = "infra-operator-001"


# ─────────────────────────────────────────────────────────────────────────────
# helpers de presentación
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
# PASO 0 — registrar ambos agentes
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
        "max_operations_per_hour": 100,
        "read_only": False,
    }
    r = httpx.post(f"{REGISTRY}/api/agents", json=payload, timeout=15.0)
    r.raise_for_status()
    return r.json()


def paso0_registrar_agentes() -> tuple[dict, dict]:
    banner("PASO 0 — La organización registra ambos agentes")

    step(f"Registrando Agent1 (Incident Manager) con ID '{AGENT1_ID}'")
    reg1 = register_agent(
        AGENT1_ID,
        scope=[
            "read:incidents",
            "execute:restart_service",
            "execute:notify_stakeholders",
            "execute:database_backup",   # puede PEDIR backup a Agent2
            "read:system_metrics",
        ],
        context="incident-management",
    )
    ok(f"Agent1 registrado")
    info("agent_did",    reg1["agent_did"])
    info("scope",        ["read:incidents","execute:restart_service","execute:database_backup","read:system_metrics"])
    info("offer_uri",    reg1["credential_offer_uri"])

    step(f"Registrando Agent2 (Infra Operator) con ID '{AGENT2_ID}'")
    reg2 = register_agent(
        AGENT2_ID,
        scope=[
            "execute:database_backup",
            "read:system_metrics",
            "execute:scale_service",
        ],
        context="infra-operations",
    )
    ok(f"Agent2 registrado")
    info("agent_did",  reg2["agent_did"])
    info("scope",      ["execute:database_backup","read:system_metrics","execute:scale_service"])
    info("offer_uri",  reg2["credential_offer_uri"])

    return reg1, reg2


# ─────────────────────────────────────────────────────────────────────────────
# PASO 1 — obtener credenciales vía OID4VCI
# ─────────────────────────────────────────────────────────────────────────────

def fetch_credential(agent_id: str, registration: dict) -> AgentHolder:
    custody = build_custody(f"agent-{agent_id}")
    holder  = AgentHolder(custody)
    offer   = httpx.get(registration["credential_offer_uri"], timeout=10.0).raise_for_status().json()
    held    = holder.fetch_credential(credential_offer=offer)

    cred_path = f"./data/agents/{agent_id}.vc.json"
    holder.save_credential(cred_path)

    step(f"Contenido de la Mandate Credential de {agent_id} (JWT decodificado)")
    payload  = _decode_jwt_payload(held.vc_jwt)
    vc_inner = payload.get("vc", {})
    cs       = vc_inner.get("credentialSubject", {})
    mandate  = cs.get("mandate", {})
    info("jti (id único)", payload.get("jti", "-"))
    info("iss (issuer DID)", payload.get("iss", "-"))
    info("sub (agente DID)", payload.get("sub", "-"))
    info("scope autorizado", mandate.get("scope", []))
    info("contexto", mandate.get("context", "-"))

    return holder


def paso1_obtener_credenciales(reg1: dict, reg2: dict) -> tuple[AgentHolder, AgentHolder]:
    banner("PASO 1 — Cada agente obtiene su Mandate Credential (OID4VCI)")

    step(f"Agent1 ({AGENT1_ID}) iniciando flujo OID4VCI…")
    holder1 = fetch_credential(AGENT1_ID, reg1)
    ok("Agent1 tiene su Mandate Credential")

    step(f"Agent2 ({AGENT2_ID}) iniciando flujo OID4VCI…")
    holder2 = fetch_credential(AGENT2_ID, reg2)
    ok("Agent2 tiene su Mandate Credential")

    return holder1, holder2


# ─────────────────────────────────────────────────────────────────────────────
# PASO 2 — identificación mutua
# ─────────────────────────────────────────────────────────────────────────────

def paso2_identificacion_mutua(holder1: AgentHolder, holder2: AgentHolder) -> None:
    banner("PASO 2 — Identificación mutua entre agentes")

    step("Agent1 arranca el peer server de Agent2 (en este demo, en el mismo proceso)")
    # (ya arrancado antes del demo)

    step("Agent1 se identifica ante Agent2")
    client1 = PeerClient(holder1, AGENT2_URL)
    result  = client1.identify()

    if result.get("verified"):
        ok("Agent1 identificado por Agent2 ✓")
        ok(f"Agent1 verificó la VC de Agent2: {result.get('peer_vc_verified', False)} ✓")
    else:
        warn(f"Identificación fallida: {result.get('message')}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# PASO 3 — Agent1 solicita acción a Agent2 (con mandato)
# ─────────────────────────────────────────────────────────────────────────────

def paso3_accion_autorizada(holder1: AgentHolder) -> None:
    banner("PASO 3 — Agent1 solicita a Agent2: execute:database_backup (AUTORIZADO)")

    step("Agent1 tiene 'execute:database_backup' en su mandato → Agent2 debe aceptar")
    client1 = PeerClient(holder1, AGENT2_URL)
    result  = client1.request_action(
        action="execute:database_backup",
        params={"database": "incidents-db", "mode": "incremental"},
        context="incident-management",
        environment="prod",
    )

    if result.get("authorized"):
        ok("Acción AUTORIZADA y ejecutada por Agent2")
        info("resultado", result.get("result"))
        info("ejecutado por", result.get("executed_by"))
    else:
        warn(f"DENEGADA (inesperado): {result.get('reason')}")


# ─────────────────────────────────────────────────────────────────────────────
# PASO 4 — Agent1 solicita acción NO en su mandato (DENEGADO)
# ─────────────────────────────────────────────────────────────────────────────

def paso4_accion_denegada(holder1: AgentHolder) -> None:
    banner("PASO 4 — Agent1 solicita execute:scale_service (DENEGADO — fuera de scope)")

    step("Agent1 NO tiene 'execute:scale_service' en su mandato → debe ser rechazado")
    client1 = PeerClient(holder1, AGENT2_URL)
    result  = client1.request_action(
        action="execute:scale_service",
        params={"service": "auth-api", "replicas": 5},
        context="incident-management",
        environment="prod",
    )

    if not result.get("authorized"):
        ok(f"Acción DENEGADA correctamente")
        info("motivo", result.get("reason"))
        info("rule_id", result.get("rule_id"))
    else:
        warn("Se esperaba denegación, pero fue autorizado. Revisa el scope.")


# ─────────────────────────────────────────────────────────────────────────────
# PASO 5 — Revocación del mandato de Agent1
# ─────────────────────────────────────────────────────────────────────────────

def paso5_revocacion(holder1: AgentHolder) -> None:
    banner("PASO 5 — La organización revoca el mandato de Agent1")

    step("Llamando al endpoint de revocación del Issuer")
    r = httpx.post(f"{ISSUER}/admin/revoke", json={"agent_did": holder1.did}, timeout=10.0)
    r.raise_for_status()
    info("respuesta del issuer", r.json())

    time.sleep(0.5)

    step("Agent1 intenta de nuevo execute:database_backup (ahora revocado)")
    client1 = PeerClient(holder1, AGENT2_URL)
    result  = client1.request_action(
        action="execute:database_backup",
        params={"database": "incidents-db", "mode": "incremental"},
        context="incident-management",
        environment="prod",
    )

    if not result.get("authorized") and result.get("rule_id") == "REVOKED":
        ok("DENEGADA por revocación — Agent2 detectó el bit en el Bitstring Status List")
        info("motivo", result.get("reason"))
    else:
        warn(f"No se denegó por revocación. Estado: {result}")


# ─────────────────────────────────────────────────────────────────────────────
# Arranque del peer server de Agent2 en un hilo
# ─────────────────────────────────────────────────────────────────────────────

def start_peer_server(holder2: AgentHolder) -> None:
    import uvicorn
    init_server(holder2)
    config = uvicorn.Config(
        peer_app,
        host="0.0.0.0",
        port=8010,
        log_level="warning",   # silenciamos los logs HTTP de uvicorn en el demo
    )
    server = uvicorn.Server(config)

    t = Thread(target=server.run, daemon=True)
    t.start()
    # Esperar a que esté listo
    import time as _time
    for _ in range(20):
        try:
            httpx.get(f"{AGENT2_URL}/peer/health", timeout=1.0).raise_for_status()
            print(f"[DEMO] Peer server de Agent2 listo en {AGENT2_URL}", flush=True)
            return
        except Exception:
            _time.sleep(0.5)
    raise RuntimeError("El peer server de Agent2 no arrancó en tiempo")


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def check_services() -> None:
    step("Comprobando servicios base arrancados")
    for name, url in [("issuer", ISSUER), ("verifier", VERIFIER), ("registry_ui", REGISTRY)]:
        try:
            httpx.get(f"{url}/health", timeout=3.0).raise_for_status()
            ok(f"{name} → {url}")
        except Exception as e:
            warn(f"{name} en {url} no responde: {e}")
            print("\n  Asegúrate de tener arrancados los 3 servicios base:")
            print("    uvicorn issuer.main:app --port 8000 &")
            print("    uvicorn verifier.main:app --port 8001 &")
            print("    uvicorn registry_ui.main:app --port 8002 &")
            sys.exit(2)


def main() -> int:
    banner("AgentTrust — Demo A2A (Agent-to-Agent) end-to-end")
    info("issuer",      ISSUER)
    info("verifier",    VERIFIER)
    info("registry_ui", REGISTRY)
    info("agent2_url",  AGENT2_URL)
    info("custody",     os.getenv("KEY_CUSTODY_BACKEND", "local"))

    check_services()

    # PASO 0 — registro
    reg1, reg2 = paso0_registrar_agentes()

    # PASO 1 — credenciales
    holder1, holder2 = paso1_obtener_credenciales(reg1, reg2)

    # Arrancar peer server de Agent2 en background (dentro del mismo proceso del demo)
    step("Arrancando peer server de Agent2 en background (puerto 8010)…")
    start_peer_server(holder2)

    # PASO 2 — identificación mutua
    paso2_identificacion_mutua(holder1, holder2)

    # PASO 3 — acción autorizada
    paso3_accion_autorizada(holder1)

    # PASO 4 — acción denegada por scope
    paso4_accion_denegada(holder1)

    # PASO 5 — revocación
    paso5_revocacion(holder1)

    banner("Demo A2A completada — protocolo Agent-to-Agent validado end-to-end")
    print("""
  Resumen del flujo demostrado:
    ✓ Dos agentes con identidad criptográfica emitida por la organización
    ✓ Identificación mutua: cada agente verifica la VC del otro
    ✓ Agent1 presenta su mandato (VP JWT) a Agent2 antes de cada acción
    ✓ Agent2 verifica la cadena completa de forma autónoma (sin humano)
    ✓ Acción dentro del scope → AUTORIZADA y ejecutada
    ✓ Acción fuera del scope → DENEGADA
    ✓ Mandato revocado → DENEGADA aunque el JWT no haya expirado
    """)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
