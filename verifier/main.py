"""
verifier/main.py

Verificador OID4VP. Es la pieza que valida H3: el agente presenta su
Mandate Credential de forma totalmente autónoma (sin humano en el loop)
y el verifier autoriza o deniega.

Flow simplificado:

  1) Agente:    POST /authorize-action {"action": ..., "context": ...}
  2) Verifier:  responde con un Authorization Request (challenge_id,
                presentation_definition, nonce)
  3) Agente:    construye una VP JWT que envuelve la VC + proof de holder
                binding (firma con su clave privada vinculada al did:key)
  4) Agente:    POST /present {"challenge_id": ..., "vp_token": ...}
  5) Verifier:  valida cadena de confianza completa, evalúa policy,
                AUTORIZA o DENIEGA y registra la decisión.

Toda la cadena de confianza:
  - VP firmada por el agente (did:key)        ← holder binding
  - VC contenida firmada por la organización  ← issuer binding
  - Issuer DID en trust framework             ← organizational trust
  - VC no revocada (Bitstring Status List)    ← real-time status
  - Mandato cubre la acción solicitada        ← scope/constraints/validity
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import uuid
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared import (
    parse_jwt_unverified,
    public_jwk_for_did_key,
    public_jwk_for_did_web,
    verify_jwt_with_jwk,
    verify_mandate_vc_jwt,
    now_ts,
    JWTVerifyError,
)

from .policy import ActionRequest, evaluate_mandate, is_revoked, PolicyDecision
from .trust_framework import is_trusted_issuer


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

load_dotenv()

VERIFIER_BASE_URL = os.getenv("VERIFIER_BASE_URL", "http://localhost:8001")
CHALLENGE_TTL_SECONDS = 300

# In-memory store de challenges activos. Para el spike basta con un dict
# protegido por lock; el TTL es muy corto.
_challenges: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[verifier] Iniciado en {VERIFIER_BASE_URL}")
    yield


app = FastAPI(title="AgentTrust Verifier", lifespan=lifespan)


# ---------------------------------------------------------------------------
# (1) /authorize-action — el agente declara la acción que quiere ejecutar
# ---------------------------------------------------------------------------

class AuthorizeActionRequest(BaseModel):
    action: str
    context: str
    resource: str | None = None
    environment: str | None = None


class AuthorizeActionResponse(BaseModel):
    challenge_id: str
    nonce: str
    presentation_definition: dict[str, Any]
    presentation_endpoint: str


@app.post("/authorize-action", response_model=AuthorizeActionResponse)
def authorize_action(req: AuthorizeActionRequest):
    """
    Construye el Authorization Request OID4VP para el flow de presentación.
    """
    challenge_id = str(uuid.uuid4())
    nonce = secrets.token_urlsafe(24)

    presentation_definition = {
        "id": f"agentmandate-{challenge_id}",
        "input_descriptors": [
            {
                "id": "agent_mandate",
                "name": "Agent Mandate Credential",
                "format": {"jwt_vc_json": {"alg": ["EdDSA"]}},
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vc.type"],
                            "filter": {
                                "type": "array",
                                "contains": {"const": "AgentMandateCredential"},
                            },
                        }
                    ]
                },
            }
        ],
    }

    with _lock:
        _challenges[challenge_id] = {
            "nonce": nonce,
            "expires_at": now_ts() + CHALLENGE_TTL_SECONDS,
            "action": req.model_dump(),
            "consumed": False,
        }

    return AuthorizeActionResponse(
        challenge_id=challenge_id,
        nonce=nonce,
        presentation_definition=presentation_definition,
        presentation_endpoint=f"{VERIFIER_BASE_URL}/present",
    )


# ---------------------------------------------------------------------------
# (2) /present — el agente envía la VP
# ---------------------------------------------------------------------------

class PresentRequest(BaseModel):
    challenge_id: str
    vp_token: str
    presentation_submission: dict[str, Any] | None = None


class PresentResponse(BaseModel):
    authorized: bool
    reason: str
    rule_id: str | None = None
    decision_id: str
    challenge_id: str


def _vlog(step: str, msg: str) -> None:
    print(f"[VERIFIER:{step}] {msg}", flush=True)


def _deny(reason: str, decision_id: str, challenge_id: str, rule_id: str | None = None, step: str = "ERROR") -> PresentResponse:
    _vlog(step, f"❌ DENEGADO — {reason}")
    return PresentResponse(
        authorized=False, reason=reason, rule_id=rule_id,
        decision_id=decision_id, challenge_id=challenge_id,
    )


@app.post("/present", response_model=PresentResponse)
def present(req: PresentRequest):
    """
    Validación completa de la VP y evaluación de la política.
    """
    decision_id = str(uuid.uuid4())

    _vlog("INICIO", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    _vlog("INICIO", f"Recibida presentación de credencial (VP)")
    _vlog("INICIO", f"  challenge_id : {req.challenge_id}")
    _vlog("INICIO", f"  decision_id  : {decision_id}")

    # ---- 1. challenge ----
    _vlog("CHALLENGE", "[1/7] Verificando challenge (anti-replay)…")
    with _lock:
        ch = _challenges.get(req.challenge_id)
        if ch is None:
            return _deny("challenge desconocido", decision_id, req.challenge_id, step="CHALLENGE")
        if ch["consumed"]:
            return _deny("challenge ya consumido", decision_id, req.challenge_id, step="CHALLENGE")
        if ch["expires_at"] < now_ts():
            return _deny("challenge expirado", decision_id, req.challenge_id, step="CHALLENGE")
        ch["consumed"] = True
        action_data = ch["action"]
        nonce = ch["nonce"]
    _vlog("CHALLENGE", f"      ✓ Challenge válido. Acción solicitada: '{action_data['action']}' / contexto: '{action_data['context']}'")

    # ---- 2. parsear y validar VP JWT ----
    _vlog("VP", "[2/7] Parseando y verificando la firma del VP JWT (holder binding)…")
    try:
        vp_header, vp_payload, _, _ = parse_jwt_unverified(req.vp_token)
    except Exception as e:
        return _deny(f"VP JWT mal formado: {e}", decision_id, req.challenge_id, step="VP")

    holder_kid = vp_header.get("kid", "")
    if not holder_kid.startswith("did:key:"):
        return _deny(f"kid del VP no es did:key: {holder_kid}", decision_id, req.challenge_id, step="VP")
    holder_did = holder_kid.split("#", 1)[0]

    _vlog("VP", f"      DID del agente (holder) : {holder_did}")

    try:
        holder_jwk = public_jwk_for_did_key(holder_did)
        verify_jwt_with_jwk(req.vp_token, holder_jwk)
    except Exception as e:
        return _deny(f"firma del VP inválida: {e}", decision_id, req.challenge_id, step="VP")

    _vlog("VP", "      ✓ Firma del VP verificada con la clave pública derivada del did:key del agente")

    if vp_payload.get("nonce") != nonce:
        return _deny("nonce del VP no coincide con el del challenge", decision_id, req.challenge_id, step="VP")
    if vp_payload.get("aud") != VERIFIER_BASE_URL:
        return _deny("aud del VP no coincide con el verifier", decision_id, req.challenge_id, step="VP")
    _vlog("VP", "      ✓ Nonce y audience correctos")

    # ---- 3. extraer VC del VP ----
    _vlog("VC", "[3/7] Extrayendo Verifiable Credential del VP…")
    vp = vp_payload.get("vp", {})
    vc_jwts = vp.get("verifiableCredential", [])
    if not vc_jwts:
        return _deny("VP sin verifiableCredential", decision_id, req.challenge_id, step="VC")
    if isinstance(vc_jwts, str):
        vc_jwts = [vc_jwts]
    vc_jwt = vc_jwts[0]
    _vlog("VC", f"      VC JWT encontrada en el VP ({len(vc_jwt)} bytes)")

    # ---- 4. verificar firma del VC y trust framework ----
    _vlog("TRUST", "[4/7] Verificando issuer y firma del VC…")
    try:
        vc_header, vc_payload, _, _ = parse_jwt_unverified(vc_jwt)
    except Exception as e:
        return _deny(f"VC JWT mal formado: {e}", decision_id, req.challenge_id, step="TRUST")

    issuer_did = vc_payload.get("iss")
    if not issuer_did:
        return _deny("VC sin claim 'iss'", decision_id, req.challenge_id, step="TRUST")

    _vlog("TRUST", f"      Issuer del VC : {issuer_did}")

    if not is_trusted_issuer(issuer_did):
        return _deny(f"issuer {issuer_did} no está en el trust framework", decision_id, req.challenge_id, step="TRUST")
    _vlog("TRUST", "      ✓ Issuer reconocido en el trust framework")

    try:
        kid = vc_header.get("kid", "")
        fragment = kid.split("#", 1)[1] if "#" in kid else None
        issuer_jwk = public_jwk_for_did_web(issuer_did, key_id=fragment)
        vc = verify_mandate_vc_jwt(vc_jwt, issuer_jwk)
    except Exception as e:
        return _deny(f"firma del VC inválida o tipo incorrecto: {e}", decision_id, req.challenge_id, step="TRUST")
    _vlog("TRUST", "      ✓ Firma del VC verificada con la clave pública del did:web del issuer")

    # ---- 5. holder binding ----
    _vlog("BINDING", "[5/7] Comprobando holder binding (VP.holder == VC.credentialSubject.id)…")
    vc_subject_id = vc.get("credentialSubject", {}).get("id")
    if vc_subject_id != holder_did:
        return _deny(
            f"holder del VP ({holder_did}) no coincide con el sujeto del VC ({vc_subject_id})",
            decision_id, req.challenge_id, step="BINDING",
        )
    _vlog("BINDING", f"      ✓ Holder binding correcto: {holder_did}")

    # ---- 6. revocación ----
    _vlog("REVOCACIÓN", "[6/7] Consultando estado de revocación (Bitstring Status List)…")
    revoked, reason = is_revoked(vc, issuer_jwk)
    if revoked:
        _vlog("REVOCACIÓN", f"      ✗ Credencial REVOCADA: {reason}")
        return _deny(f"revocada: {reason}", decision_id, req.challenge_id, rule_id="REVOKED", step="REVOCACIÓN")
    _vlog("REVOCACIÓN", "      ✓ Credencial NO revocada")

    # ---- 7. policy ----
    _vlog("POLICY", "[7/7] Evaluando política de mandato…")
    cs = vc.get("credentialSubject", {})
    mandate_data = cs.get("mandate", {})
    _vlog("POLICY", f"      Scope en la VC        : {mandate_data.get('scope', [])}")
    _vlog("POLICY", f"      Acción solicitada     : {action_data['action']}")
    _vlog("POLICY", f"      Contexto solicitado   : {action_data['context']}")
    _vlog("POLICY", f"      Entorno solicitado    : {action_data.get('environment', '-')}")

    decision: PolicyDecision = evaluate_mandate(
        vc,
        ActionRequest(
            action=action_data["action"],
            context=action_data["context"],
            resource=action_data.get("resource"),
            environment=action_data.get("environment"),
        ),
    )

    if decision.authorized:
        _vlog("DECISIÓN", f"✅ AUTORIZADO — rule={decision.rule_id} | {decision.reason}")
    else:
        _vlog("DECISIÓN", f"❌ DENEGADO   — rule={decision.rule_id} | {decision.reason}")
    _vlog("DECISIÓN", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    return PresentResponse(
        authorized=decision.authorized,
        reason=decision.reason,
        rule_id=decision.rule_id,
        decision_id=decision_id,
        challenge_id=req.challenge_id,
    )


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}
