"""
agent/main.py

Punto de entrada CLI del agente. Modos de uso:

  # Solo recibir credencial (H1+H2)
  python -m agent.main fetch \\
      --credential-offer-uri http://localhost:8000/credential-offer/abc123 \\
      --agent-id agent-001

  # Recibir credencial Y ejecutar una tool (H1+H2+H3)
  python -m agent.main run \\
      --credential-offer-uri ... \\
      --agent-id agent-001 \\
      --tool restart_service \\
      --arg service_name=auth-api

  # Solo ejecutar una tool con credencial guardada de antes
  python -m agent.main run \\
      --agent-id agent-001 \\
      --tool restart_service \\
      --arg service_name=auth-api

El agent-id determina el `key_name` que se usa en KeyCustody, y por tanto
qué clave Ed25519 controla este proceso. Cambiar de agent-id = otro agente
distinto, otro did:key, otro VC.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

from shared import build_custody

from .holder import AgentHolder
from .runtime import AgentRuntime
from .tools import DEFAULT_TOOLS


load_dotenv()


def _credential_path(agent_id: str) -> str:
    base = os.getenv("AGENT_CREDENTIAL_DIR", "./data/agents")
    return f"{base}/{agent_id}.vc.json"


def _build_holder(agent_id: str) -> AgentHolder:
    """
    Crea el holder con la custodia configurada (`KEY_CUSTODY_BACKEND`).
    El nombre de clave es `agent-<agent_id>`, que mapea a:
      - `./data/keys/agent-<agent_id>.priv`  (LocalFile)
      - `transit/keys/agent-<agent_id>`      (Vault)
    """
    custody = build_custody(f"agent-{agent_id}")
    return AgentHolder(custody)


def _print_summary(holder: AgentHolder) -> None:
    print(f"  agent_did    = {holder.did}")
    print(f"  custody      = {holder.custody.key_id}")
    print(f"  algorithm    = {holder.custody.algorithm}")


# ---------------------------------------------------------------------------
# subcomandos
# ---------------------------------------------------------------------------

def cmd_fetch(args) -> int:
    holder = _build_holder(args.agent_id)
    print("[agent] Identidad inicializada:")
    _print_summary(holder)

    # Resolver el credential_offer
    if args.credential_offer_uri:
        print(f"[agent] Descargando credential_offer de {args.credential_offer_uri}")
        offer = httpx.get(args.credential_offer_uri, timeout=10.0).raise_for_status().json()
    elif args.credential_offer_file:
        with open(args.credential_offer_file, "r", encoding="utf-8") as f:
            offer = json.load(f)
    else:
        print("ERROR: debes proporcionar --credential-offer-uri o --credential-offer-file", file=sys.stderr)
        return 2

    print("[agent] Ejecutando OID4VCI Pre-Authorized Code Flow...")
    held = holder.fetch_credential(credential_offer=offer)
    print(f"[agent] VC recibida del issuer {held.issuer_did}")

    cred_path = _credential_path(args.agent_id)
    holder.save_credential(cred_path)
    print(f"[agent] VC persistida en {cred_path}")
    return 0


def cmd_run(args) -> int:
    holder = _build_holder(args.agent_id)
    print("[agent] Identidad inicializada:")
    _print_summary(holder)

    # Cargar credencial existente o ir a buscarla
    cred_path = _credential_path(args.agent_id)
    if not holder.load_credential(cred_path):
        if args.credential_offer_uri:
            offer = httpx.get(args.credential_offer_uri, timeout=10.0).raise_for_status().json()
            holder.fetch_credential(credential_offer=offer)
            holder.save_credential(cred_path)
            print(f"[agent] VC obtenida y guardada en {cred_path}")
        else:
            print(
                f"ERROR: no hay credencial en {cred_path} y no diste --credential-offer-uri",
                file=sys.stderr,
            )
            return 2
    else:
        print(f"[agent] VC cargada desde {cred_path}")

    if not args.tool:
        print("[agent] No se especificó --tool, salgo (modo bootstrap-only).")
        return 0

    if args.tool not in DEFAULT_TOOLS:
        print(f"ERROR: tool '{args.tool}' desconocida. Disponibles: {list(DEFAULT_TOOLS)}", file=sys.stderr)
        return 2

    # Parsear --arg key=value
    tool_kwargs: dict[str, str] = {}
    for raw in args.arg or []:
        if "=" not in raw:
            print(f"ERROR: --arg malformado: {raw} (esperaba clave=valor)", file=sys.stderr)
            return 2
        k, v = raw.split("=", 1)
        tool_kwargs[k] = v

    runtime = AgentRuntime(holder, verifier_url=os.getenv("VERIFIER_BASE_URL", "http://localhost:8001"))
    print(f"[agent] Intentando ejecutar tool='{args.tool}' con args={tool_kwargs}")
    record = runtime.call_tool(args.tool, **tool_kwargs)

    print()
    print("=" * 60)
    print(f"  Authorized : {record.authorized}")
    print(f"  Rule       : {record.rule_id}")
    print(f"  Reason     : {record.reason}")
    if record.result is not None:
        print(f"  Result     : {json.dumps(record.result, indent=2, ensure_ascii=False)}")
    print("=" * 60)
    return 0 if record.authorized else 1


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent", description="AgentTrust spike — agente CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_fetch = sub.add_parser("fetch", help="Solo recibir VC (OID4VCI)")
    p_fetch.add_argument("--agent-id", required=True)
    p_fetch.add_argument("--credential-offer-uri")
    p_fetch.add_argument("--credential-offer-file")
    p_fetch.set_defaults(func=cmd_fetch)

    p_run = sub.add_parser("run", help="Recibir VC (si hace falta) y ejecutar una tool")
    p_run.add_argument("--agent-id", required=True)
    p_run.add_argument("--credential-offer-uri")
    p_run.add_argument("--tool")
    p_run.add_argument("--arg", action="append", help="argumento de la tool en formato clave=valor")
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
