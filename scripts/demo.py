#!/usr/bin/env python3
"""
scripts/demo.py

Demo end-to-end del spike. Recorre las 4 hipótesis con output legible
para que sirva de pieza de los 5-10 minutos que pide el criterio de cierre.

Prerrequisitos antes de lanzar:
  1. Las tres aplicaciones FastAPI deben estar arrancadas:
       - issuer       → http://localhost:8000
       - verifier     → http://localhost:8001
       - registry_ui  → http://localhost:8002
  2. Bootstrap ejecutado al menos una vez:  python scripts/bootstrap_org.py
  3. (Opcional) Vault corriendo si KEY_CUSTODY_BACKEND=vault

Recorrido:
  H0 — registra un agente vía API del Registry UI
  H1 — el agente arranca y obtiene su Mandate Credential vía OID4VCI
  H2 — la clave del agente está en el backend de custodia (no en claro)
  H3a — el agente intenta una acción dentro del scope → AUTORIZADA
  H3b — el agente intenta una acción FUERA del scope → DENEGADA
  Revocación — la organización revoca; la siguiente acción se rechaza
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Permite ejecutar el script directamente
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import base64
import json as _json

import httpx
from dotenv import load_dotenv

load_dotenv()

from shared import build_custody, did_key_from_custody  # noqa: E402
from agent.holder import AgentHolder  # noqa: E402
from agent.runtime import AgentRuntime  # noqa: E402


def _decode_jwt_payload(jwt_str: str) -> dict:
    part = jwt_str.split(".")[1]
    part += "=" * (-len(part) % 4)
    return _json.loads(base64.urlsafe_b64decode(part))


ISSUER = os.getenv("ISSUER_BASE_URL", "http://localhost:8000")
VERIFIER = os.getenv("VERIFIER_BASE_URL", "http://localhost:8001")
REGISTRY = os.getenv("REGISTRY_UI_BASE_URL", "http://localhost:8002")

AGENT_ID = "demo-agent-001"


# ---------------------------------------------------------------------------
# pretty print helpers
# ---------------------------------------------------------------------------

def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def step(msg: str) -> None:
    print(f"\n→ {msg}")


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def warn(msg: str) -> None:
    print(f"  ✗ {msg}")


def info(label: str, value) -> None:
    print(f"    {label:<22} {value}")


# ---------------------------------------------------------------------------
# checks previos
# ---------------------------------------------------------------------------

def check_services() -> None:
    step("Comprobando servicios arrancados")
    for name, url in [("issuer", ISSUER), ("verifier", VERIFIER), ("registry_ui", REGISTRY)]:
        try:
            r = httpx.get(f"{url}/health", timeout=3.0)
            r.raise_for_status()
            ok(f"{name:<12} {url}  → {r.json()}")
        except Exception as e:
            warn(f"{name} en {url} no responde: {e}")
            print()
            print("  Antes de lanzar el demo asegúrate de tener arrancados los 3 servicios:")
            print("    uvicorn issuer.main:app --port 8000 &")
            print("    uvicorn verifier.main:app --port 8001 &")
            print("    uvicorn registry_ui.main:app --port 8002 &")
            sys.exit(2)


# ---------------------------------------------------------------------------
# H0 — alta del agente
# ---------------------------------------------------------------------------

def h0_register_agent() -> dict:
    banner("H0 — Alta del agente desde el Registry UI")
    step(f"POST {REGISTRY}/api/agents")

    valid_from = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    valid_until = (datetime.now(tz=timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "agent_id": AGENT_ID,
        "delegator_did": f"{os.getenv('ORG_DID', 'did:web:localhost%3A8000')}#supervisor-001",
        "scope": [
            "read:incidents",
            "execute:restart_service",
            "execute:notify_stakeholders",
        ],
        "context": "incident-management",
        "valid_from": valid_from,
        "valid_until": valid_until,
        "allowed_environments": ["prod", "staging"],
        "max_operations_per_hour": 100,
        "read_only": False,
    }

    r = httpx.post(f"{REGISTRY}/api/agents", json=payload, timeout=10.0)
    r.raise_for_status()
    data = r.json()

    ok("Agente dado de alta")
    info("agent_id", data["agent_id"])
    info("agent_did", data["agent_did"])
    info("offer_uri", data["credential_offer_uri"])
    info("scope autorizado", payload["scope"])

    return data


# ---------------------------------------------------------------------------
# H1+H2 — el agente recibe su credencial
# ---------------------------------------------------------------------------

def h1_h2_fetch_credential(registration: dict) -> AgentHolder:
    banner("H1 + H2 — El agente obtiene su Mandate Credential vía OID4VCI")

    custody = build_custody(f"agent-{AGENT_ID}")
    holder = AgentHolder(custody)

    step("Identidad criptográfica del agente")
    info("custody backend", custody.key_id)
    info("algoritmo", custody.algorithm)
    info("did:key asignado", holder.did)
    info("coincide con el alta", holder.did == registration["agent_did"])

    step("Ejecutando OID4VCI Pre-Authorized Code Flow")
    info("credential_offer_uri", registration["credential_offer_uri"])

    offer = httpx.get(registration["credential_offer_uri"], timeout=10.0).raise_for_status().json()
    held = holder.fetch_credential(credential_offer=offer)

    ok("VC recibida y firmada por la organización")
    info("issuer del VC", held.issuer_did)
    info("longitud VC JWT", f"{len(held.vc_jwt)} bytes")

    step("Contenido de la Mandate Credential (JWT decodificado)")
    payload = _decode_jwt_payload(held.vc_jwt)
    vc_inner = payload.get("vc", {})
    cs = vc_inner.get("credentialSubject", {})
    mandate = cs.get("mandate", {})
    print(f"    {'jti (id único)':<26} {payload.get('jti', '-')}")
    print(f"    {'iss (emisor DID)':<26} {payload.get('iss', '-')}")
    print(f"    {'sub (agente DID)':<26} {payload.get('sub', '-')}")
    print(f"    {'tipo VC':<26} {vc_inner.get('type', [])}")
    print(f"    {'scope autorizado':<26} {mandate.get('scope', [])}")
    print(f"    {'contexto':<26} {mandate.get('context', '-')}")
    print(f"    {'entornos':<26} {mandate.get('constraints', {}).get('allowed_environments', [])}")
    print(f"    {'revocación index':<26} {vc_inner.get('credentialStatus', {}).get('statusListIndex', '-')}")

    cred_path = f"./data/agents/{AGENT_ID}.vc.json"
    holder.save_credential(cred_path)
    ok(f"VC persistida en {cred_path}")

    step("H2 — custodia de clave (la clave privada nunca sale del backend)")
    info("backend", custody.key_id)
    if custody.key_id.startswith("vault::"):
        info("mecanismo", "cada firma → POST http://localhost:8200/v1/transit/sign/<key>")
        info("garantía", "la clave privada NUNCA abandona Vault")
    else:
        info("mecanismo", "clave Ed25519 en fichero local (modo dev sin Vault)")

    return holder


# ---------------------------------------------------------------------------
# H3 — presentación autónoma
# ---------------------------------------------------------------------------

def h3_authorized_action(holder: AgentHolder) -> None:
    banner("H3a — Acción DENTRO del scope (debe AUTORIZARSE)")
    runtime = AgentRuntime(holder, verifier_url=VERIFIER)

    step("call_tool('restart_service', service_name='auth-api')")
    info("action requested", "execute:restart_service")
    info("context", "incident-management")
    info("environment", "prod")

    record = runtime.call_tool("restart_service", service_name="auth-api")

    if record.authorized:
        ok(f"AUTORIZADA — rule={record.rule_id}, reason={record.reason}")
        info("decision_id", record.decision_id)
        info("resultado tool", record.result)
    else:
        warn(f"DENEGADA — rule={record.rule_id}: {record.reason}")
        sys.exit(1)


def h3_denied_action(holder: AgentHolder) -> None:
    banner("H3b — Acción FUERA del scope (debe DENEGARSE)")
    runtime = AgentRuntime(holder, verifier_url=VERIFIER)

    step("call_tool('escalate_to_human', ...) — no está en el scope")
    info("action requested", "execute:escalate_to_human")

    record = runtime.call_tool("escalate_to_human", incident_id="INC-9001", reason="demo")

    if not record.authorized:
        ok(f"DENEGADA correctamente — rule={record.rule_id}")
        info("reason", record.reason)
    else:
        warn("⚠ DENEGACIÓN ESPERADA, pero el verifier autorizó. Revisa policy.")


# ---------------------------------------------------------------------------
# Bonus — revocación
# ---------------------------------------------------------------------------

def revocation_flow(holder: AgentHolder) -> None:
    banner("Revocación — el mandato se revoca en caliente")
    step("La organización revoca el mandato")
    r = httpx.post(
        f"{ISSUER}/admin/revoke",
        json={"agent_did": holder.did},
        timeout=10.0,
    )
    r.raise_for_status()
    info("respuesta del issuer", r.json())

    # Pequeño wait para garantizar que el siguiente fetch del status list
    # vea el cambio (es la misma DB, pero damos margen).
    time.sleep(0.5)

    step("Reintentamos la acción que antes estaba autorizada")
    runtime = AgentRuntime(holder, verifier_url=VERIFIER)
    record = runtime.call_tool("restart_service", service_name="auth-api")

    if not record.authorized and (record.rule_id == "REVOKED" or "revocada" in record.reason.lower()):
        ok("DENEGADA por revocación — el verifier consultó el Bitstring Status List")
        info("rule_id", record.rule_id)
        info("reason", record.reason)
    else:
        warn("⚠ La acción no se denegó por revocación. Revisa el flow.")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    banner("AgentTrust — Demo end-to-end (H0 → H1 → H2 → H3 → revocación)")
    info("issuer", ISSUER)
    info("verifier", VERIFIER)
    info("registry_ui", REGISTRY)
    info("custody backend", os.getenv("KEY_CUSTODY_BACKEND", "local"))

    check_services()

    registration = h0_register_agent()
    holder = h1_h2_fetch_credential(registration)
    h3_authorized_action(holder)
    h3_denied_action(holder)
    revocation_flow(holder)

    banner("Demo completada — las 4 hipótesis ejercitadas end-to-end")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
