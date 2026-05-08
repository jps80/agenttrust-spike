"""
agent/peer_server.py

Servidor A2A (Agent-to-Agent) que corre en Agent2.

Expone 4 endpoints para el protocolo de interacción entre agentes:

  GET  /peer/health              → estado y DID de este agente
  POST /peer/identify            → identificación mutua:
                                    Agent1 presenta su VC, Agent2 verifica y
                                    devuelve la suya propia.
  POST /peer/action/challenge    → Agent1 solicita un nonce para una acción
                                    concreta (previene replay).
  POST /peer/action/submit       → Agent1 presenta su VP JWT (mandato + proof)
                                    y solicita que Agent2 ejecute la acción.
                                    Agent2 verifica la cadena completa antes
                                    de ejecutar.

La verificación del mandato no delega en el Verifier central: Agent2
la realiza directamente (misma lógica, autonomía completa entre agentes).
"""
from __future__ import annotations

import os
import secrets
import threading
import uuid
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI
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
from verifier.policy import evaluate_mandate, is_revoked, ActionRequest
from verifier.trust_framework import is_trusted_issuer
from .peer_tools import get_peer_tool, PeerTool

load_dotenv()

AGENT2_BASE_URL = os.getenv("AGENT2_BASE_URL", "http://localhost:8010")
CHALLENGE_TTL = 120  # segundos

_holder = None          # AgentHolder — se inyecta en lifespan
_challenges: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


def init_server(holder) -> None:
    """Inyecta el AgentHolder antes de arrancar el servidor."""
    global _holder
    _holder = holder


@asynccontextmanager
async def lifespan(app: FastAPI):
    if _holder is None:
        raise RuntimeError("Llama a init_server(holder) antes de arrancar peer_server")
    print(f"[AGENT2:PEER_SERVER] Servidor A2A arrancado en {AGENT2_BASE_URL}", flush=True)
    print(f"[AGENT2:PEER_SERVER]   DID de este agente : {_holder.did}", flush=True)
    print(f"[AGENT2:PEER_SERVER]   Esperando peticiones de otros agentes…", flush=True)
    yield


app = FastAPI(title="AgentTrust Peer Server (Agent2)", lifespan=lifespan)


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/peer/health")
def health():
    did = _holder.did if _holder else "not-initialized"
    cred = _holder.credential if _holder else None
    return {
        "status": "ok",
        "agent_did": did,
        "has_credential": cred is not None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# POST /peer/identify — identificación mutua
# ─────────────────────────────────────────────────────────────────────────────

class IdentifyRequest(BaseModel):
    agent_did: str
    vc_jwt: str     # Mandate Credential del agente que se presenta


class IdentifyResponse(BaseModel):
    verified: bool
    message: str
    agent_did: str | None = None
    vc_jwt: str | None = None       # VC de Agent2 para que Agent1 la verifique


@app.post("/peer/identify", response_model=IdentifyResponse)
def identify(req: IdentifyRequest):
    """
    Agent1 se presenta a Agent2 con su VC (emitida por la organización).
    Agent2 verifica:
      1. La firma de la VC (issuer de confianza).
      2. Que el sujeto de la VC coincide con el DID declarado.
      3. Que la VC no está revocada.
    Si todo es correcto, responde con su propia VC.
    """
    print(f"[AGENT2:IDENTIFY] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", flush=True)
    print(f"[AGENT2:IDENTIFY] Agente intentando identificarse:", flush=True)
    print(f"[AGENT2:IDENTIFY]   DID declarado : {req.agent_did}", flush=True)

    # 1. parsear VC
    try:
        vc_header, vc_payload, _, _ = parse_jwt_unverified(req.vc_jwt)
    except Exception as e:
        print(f"[AGENT2:IDENTIFY] ❌ VC JWT mal formada: {e}", flush=True)
        return IdentifyResponse(verified=False, message=f"VC mal formada: {e}", agent_did=_holder.did)

    issuer_did = vc_payload.get("iss", "")
    subject_did = vc_payload.get("sub", "")

    print(f"[AGENT2:IDENTIFY]   Issuer en VC  : {issuer_did}", flush=True)
    print(f"[AGENT2:IDENTIFY]   Sujeto en VC  : {subject_did}", flush=True)

    # 2. trust framework
    if not is_trusted_issuer(issuer_did):
        msg = f"issuer '{issuer_did}' no está en el trust framework"
        print(f"[AGENT2:IDENTIFY] ❌ {msg}", flush=True)
        return IdentifyResponse(verified=False, message=msg, agent_did=_holder.did)

    # 3. firma VC
    try:
        kid = vc_header.get("kid", "")
        fragment = kid.split("#", 1)[1] if "#" in kid else None
        issuer_jwk = public_jwk_for_did_web(issuer_did, key_id=fragment)
        vc = verify_mandate_vc_jwt(req.vc_jwt, issuer_jwk)
    except Exception as e:
        msg = f"firma de la VC inválida: {e}"
        print(f"[AGENT2:IDENTIFY] ❌ {msg}", flush=True)
        return IdentifyResponse(verified=False, message=msg, agent_did=_holder.did)

    print(f"[AGENT2:IDENTIFY] ✓ Firma de la VC verificada", flush=True)

    # 4. sujeto coincide con DID declarado
    vc_subject = vc.get("credentialSubject", {}).get("id", "")
    if vc_subject != req.agent_did:
        msg = f"sujeto de la VC ({vc_subject}) no coincide con DID declarado ({req.agent_did})"
        print(f"[AGENT2:IDENTIFY] ❌ {msg}", flush=True)
        return IdentifyResponse(verified=False, message=msg, agent_did=_holder.did)

    print(f"[AGENT2:IDENTIFY] ✓ Sujeto de la VC coincide con el DID declarado", flush=True)

    # 5. revocación
    revoked, reason = is_revoked(vc, issuer_jwk)
    if revoked:
        msg = f"credencial del agente está revocada: {reason}"
        print(f"[AGENT2:IDENTIFY] ❌ {msg}", flush=True)
        return IdentifyResponse(verified=False, message=msg, agent_did=_holder.did)

    print(f"[AGENT2:IDENTIFY] ✓ Credencial no revocada", flush=True)
    print(f"[AGENT2:IDENTIFY] ✅ Agente identificado correctamente. Respondiendo con la VC propia.", flush=True)

    my_vc_jwt = _holder.credential.vc_jwt if _holder.credential else None
    return IdentifyResponse(
        verified=True,
        message="Identidad verificada. Bienvenido.",
        agent_did=_holder.did,
        vc_jwt=my_vc_jwt,
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /peer/action/challenge — nonce para la presentación del mandato
# ─────────────────────────────────────────────────────────────────────────────

class ActionChallengeRequest(BaseModel):
    action: str
    params: dict[str, Any] = {}
    context: str = "incident-management"
    environment: str | None = None


class ActionChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str
    action: str


@app.post("/peer/action/challenge", response_model=ActionChallengeResponse)
def action_challenge(req: ActionChallengeRequest):
    """Agent1 solicita un nonce para presentar su mandato en la acción concreta."""
    challenge_id = str(uuid.uuid4())
    nonce = secrets.token_urlsafe(24)

    print(f"[AGENT2:CHALLENGE] Nuevo challenge para acción '{req.action}': {challenge_id}", flush=True)

    with _lock:
        _challenges[challenge_id] = {
            "nonce": nonce,
            "action": req.action,
            "params": req.params,
            "context": req.context,
            "environment": req.environment,
            "expires_at": now_ts() + CHALLENGE_TTL,
            "consumed": False,
        }

    return ActionChallengeResponse(
        challenge_id=challenge_id,
        nonce=nonce,
        action=req.action,
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /peer/action/submit — presentar mandato y ejecutar acción
# ─────────────────────────────────────────────────────────────────────────────

class ActionSubmitRequest(BaseModel):
    challenge_id: str
    vp_token: str       # VP JWT de Agent1 con su Mandate Credential
    action: str
    params: dict[str, Any] = {}


class ActionSubmitResponse(BaseModel):
    authorized: bool
    reason: str
    rule_id: str | None = None
    result: dict[str, Any] | None = None
    executed_by: str | None = None


@app.post("/peer/action/submit", response_model=ActionSubmitResponse)
def action_submit(req: ActionSubmitRequest):
    """
    Agent1 presenta su VP JWT (mandato) y solicita que Agent2 ejecute la acción.

    Verificaciones que hace Agent2 de forma autónoma:
      1. Challenge válido y no consumido.
      2. Firma del VP (holder binding del agente solicitante).
      3. Nonce correcto (anti-replay).
      4. Firma de la VC contenida en el VP (issuer de confianza).
      5. Holder binding: el sujeto de la VC == firmante del VP.
      6. Credencial no revocada.
      7. Política: el mandato cubre la acción solicitada.
    """
    print(f"[AGENT2:SUBMIT] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", flush=True)
    print(f"[AGENT2:SUBMIT] Recibida solicitud de acción con mandato VP", flush=True)
    print(f"[AGENT2:SUBMIT]   challenge_id : {req.challenge_id}", flush=True)
    print(f"[AGENT2:SUBMIT]   acción       : {req.action}", flush=True)

    def deny(reason: str, rule_id: str | None = None) -> ActionSubmitResponse:
        print(f"[AGENT2:SUBMIT] ❌ DENEGADO — {reason}", flush=True)
        return ActionSubmitResponse(authorized=False, reason=reason, rule_id=rule_id)

    # 1. challenge
    print(f"[AGENT2:SUBMIT] [1/7] Verificando challenge…", flush=True)
    with _lock:
        ch = _challenges.get(req.challenge_id)
        if ch is None:
            return deny("challenge desconocido")
        if ch["consumed"]:
            return deny("challenge ya consumido (replay detectado)")
        if ch["expires_at"] < now_ts():
            return deny("challenge expirado")
        if ch["action"] != req.action:
            return deny(f"acción del submit ('{req.action}') no coincide con la del challenge ('{ch['action']}')")
        ch["consumed"] = True
        nonce = ch["nonce"]
        context = ch["context"]
        environment = ch["environment"]
    print(f"[AGENT2:SUBMIT]   ✓ Challenge válido", flush=True)

    # 2. parsear VP JWT
    print(f"[AGENT2:SUBMIT] [2/7] Parseando y verificando firma del VP…", flush=True)
    try:
        vp_header, vp_payload, _, _ = parse_jwt_unverified(req.vp_token)
    except Exception as e:
        return deny(f"VP JWT mal formado: {e}")

    holder_kid = vp_header.get("kid", "")
    if not holder_kid.startswith("did:key:"):
        return deny(f"kid del VP no es did:key: {holder_kid}")
    holder_did = holder_kid.split("#", 1)[0]
    print(f"[AGENT2:SUBMIT]   Agente solicitante (holder DID) : {holder_did}", flush=True)

    try:
        holder_jwk = public_jwk_for_did_key(holder_did)
        verify_jwt_with_jwk(req.vp_token, holder_jwk)
    except Exception as e:
        return deny(f"firma del VP inválida: {e}")
    print(f"[AGENT2:SUBMIT]   ✓ Firma del VP verificada", flush=True)

    # 3. nonce y audience
    print(f"[AGENT2:SUBMIT] [3/7] Verificando nonce y audience…", flush=True)
    if vp_payload.get("nonce") != nonce:
        return deny("nonce del VP no coincide con el del challenge")
    if vp_payload.get("aud") != AGENT2_BASE_URL:
        return deny(f"aud del VP ('{vp_payload.get('aud')}') no apunta a este agente ('{AGENT2_BASE_URL}')")
    print(f"[AGENT2:SUBMIT]   ✓ Nonce y audience correctos", flush=True)

    # 4. extraer VC
    print(f"[AGENT2:SUBMIT] [4/7] Extrayendo VC del VP…", flush=True)
    vp = vp_payload.get("vp", {})
    vc_jwts = vp.get("verifiableCredential", [])
    if not vc_jwts:
        return deny("VP sin verifiableCredential")
    if isinstance(vc_jwts, str):
        vc_jwts = [vc_jwts]
    vc_jwt = vc_jwts[0]
    print(f"[AGENT2:SUBMIT]   VC encontrada ({len(vc_jwt)} bytes)", flush=True)

    # 5. verificar issuer y firma VC
    print(f"[AGENT2:SUBMIT] [5/7] Verificando issuer y firma de la VC…", flush=True)
    try:
        vc_header, vc_payload, _, _ = parse_jwt_unverified(vc_jwt)
    except Exception as e:
        return deny(f"VC JWT mal formada: {e}")

    issuer_did = vc_payload.get("iss", "")
    if not is_trusted_issuer(issuer_did):
        return deny(f"issuer '{issuer_did}' no está en el trust framework")

    try:
        kid = vc_header.get("kid", "")
        fragment = kid.split("#", 1)[1] if "#" in kid else None
        issuer_jwk = public_jwk_for_did_web(issuer_did, key_id=fragment)
        vc = verify_mandate_vc_jwt(vc_jwt, issuer_jwk)
    except Exception as e:
        return deny(f"firma de la VC inválida: {e}")
    print(f"[AGENT2:SUBMIT]   ✓ Issuer '{issuer_did}' de confianza, firma válida", flush=True)

    # 6. holder binding
    print(f"[AGENT2:SUBMIT] [6/7] Verificando holder binding…", flush=True)
    vc_subject = vc.get("credentialSubject", {}).get("id", "")
    if vc_subject != holder_did:
        return deny(f"sujeto de la VC ({vc_subject}) != firmante del VP ({holder_did})")
    print(f"[AGENT2:SUBMIT]   ✓ Holder binding correcto: {holder_did}", flush=True)

    # 7. revocación
    print(f"[AGENT2:SUBMIT] [7a/7] Verificando revocación…", flush=True)
    revoked, rev_reason = is_revoked(vc, issuer_jwk)
    if revoked:
        return deny(f"credencial revocada: {rev_reason}", rule_id="REVOKED")
    print(f"[AGENT2:SUBMIT]   ✓ Credencial no revocada", flush=True)

    # 7. política de mandato
    print(f"[AGENT2:SUBMIT] [7b/7] Evaluando política de mandato…", flush=True)
    cs = vc.get("credentialSubject", {})
    mandate_data = cs.get("mandate", {})
    print(f"[AGENT2:SUBMIT]   Scope en mandato de Agent1 : {mandate_data.get('scope', [])}", flush=True)
    print(f"[AGENT2:SUBMIT]   Acción solicitada           : {req.action}", flush=True)

    decision = evaluate_mandate(
        vc,
        ActionRequest(action=req.action, context=context, environment=environment),
    )

    if not decision.authorized:
        return deny(decision.reason, rule_id=decision.rule_id)

    # ── Ejecutar la acción ────────────────────────────────────────────────────
    print(f"[AGENT2:SUBMIT] ✅ Mandato válido. Ejecutando acción '{req.action}'…", flush=True)
    try:
        tool: PeerTool = get_peer_tool(req.action)
        result = tool.run(**req.params)
    except KeyError:
        result = {"warning": f"acción '{req.action}' autorizada pero sin implementación (spike)"}
    except Exception as e:
        result = {"error": str(e)}

    print(f"[AGENT2:SUBMIT]   Resultado : {result}", flush=True)
    print(f"[AGENT2:SUBMIT] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", flush=True)

    return ActionSubmitResponse(
        authorized=True,
        reason=decision.reason,
        rule_id=decision.rule_id,
        result=result,
        executed_by=_holder.did,
    )
