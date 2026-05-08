#!/usr/bin/env python3
"""
scripts/bootstrap_org.py

Inicializa la identidad de la organización emisora.

Hace tres cosas:
  1. Garantiza que existe la clave de la organización en el backend
     de custodia configurado (LocalFile o Vault).
  2. Imprime el did:web y el JWK público para verificar visualmente.
  3. Registra la organización como issuer de confianza en
     `data/trust_framework.json` (lo lee el verifier).

Idempotente: ejecutarlo dos veces no rompe nada.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Asegura que el paquete del proyecto está en el path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

from shared import build_custody, build_did_web_document  # noqa: E402
from verifier.trust_framework import add_trusted_issuer  # noqa: E402


def main() -> int:
    org_did = os.getenv("ORG_DID", "did:web:localhost%3A8000")
    issuer_key_name = "org-issuer"

    print("=" * 70)
    print("AgentTrust — Bootstrap de la organización emisora")
    print("=" * 70)
    print(f"  ORG_DID                = {org_did}")
    print(f"  KEY_CUSTODY_BACKEND    = {os.getenv('KEY_CUSTODY_BACKEND', 'local')}")
    print(f"  ISSUER_KEY_NAME        = {issuer_key_name}")
    print()

    custody = build_custody(issuer_key_name)
    pub_jwk = custody.get_public_jwk()
    pub_jwk_kid = {**pub_jwk, "kid": "key-1"}

    print(f"  Custody key_id         = {custody.key_id}")
    print(f"  Algoritmo              = {custody.algorithm}")
    print(f"  Public JWK             = {pub_jwk_kid}")
    print()

    doc = build_did_web_document(org_did, pub_jwk_kid)
    print("  did:web document que servirá el issuer:")
    print("  " + str(doc).replace("\\n", "\n  "))
    print()

    add_trusted_issuer(org_did)
    print(f"  ✓ {org_did} añadido al trust framework "
          f"({os.getenv('TRUST_FRAMEWORK_PATH', './data/trust_framework.json')})")

    print()
    print("Bootstrap completado. Ya puedes arrancar el issuer:")
    print(f"    uvicorn issuer.main:app --port {os.getenv('ISSUER_PORT', '8000')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
