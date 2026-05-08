"""
verifier/policy.py

Motor de evaluación de mandato. Recibe el VC ya firmado/verificado y la
acción que el agente quiere ejecutar; decide AUTORIZADO / DENEGADO.

Es el equivalente en miniatura del PDP del estándar AuthZEN. En producción
se sustituye por una integración AuthZEN-compatible: el verifier es el PEP,
delega la decisión a un PDP (ej. OPA, Cedar) sobre la tupla
Subject-Action-Resource-Context.
"""
from __future__ import annotations

import gzip
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from shared import (
    parse_jwt_unverified,
    verify_jwt_with_jwk,
    decode_bitstring,
    DEFAULT_STATUS_LIST_SIZE_BITS,
)


# ---------------------------------------------------------------------------
# tipos
# ---------------------------------------------------------------------------

@dataclass
class ActionRequest:
    action: str       # ej. "execute:restart_service"
    context: str      # ej. "incident-management"
    resource: str | None = None  # ej. "service:auth-api"
    environment: str | None = None  # ej. "prod"


@dataclass
class PolicyDecision:
    authorized: bool
    reason: str
    rule_id: str | None = None     # qué regla aplicó


# ---------------------------------------------------------------------------
# evaluación
# ---------------------------------------------------------------------------

def evaluate_mandate(vc: dict[str, Any], request: ActionRequest) -> PolicyDecision:
    """
    Evalúa una acción contra una Mandate Credential ya verificada.

    Reglas, por orden de severidad:
      R1. validity window — validFrom <= now <= validUntil
      R2. context — la `context` del request encaja con la del mandato
      R3. scope — la `action` solicitada está en el scope
      R4. constraints.read_only — si está activo, solo "read:..." pasa
      R5. constraints.allowed_environments — el environment debe estar permitido
    """
    cs = vc.get("credentialSubject", {})

    # R1 — validez temporal
    now = datetime.now(tz=timezone.utc)
    valid_from = _parse_iso(vc.get("validFrom"))
    valid_until = _parse_iso(vc.get("validUntil"))

    if valid_from and now < valid_from:
        return PolicyDecision(False, f"mandato aún no válido (validFrom={vc.get('validFrom')})", rule_id="R1")
    if valid_until and now > valid_until:
        return PolicyDecision(False, f"mandato expirado (validUntil={vc.get('validUntil')})", rule_id="R1")

    # R2 — context
    mandate_context = cs.get("context")
    if mandate_context and request.context != mandate_context:
        return PolicyDecision(
            False,
            f"contexto del request '{request.context}' no coincide con el del mandato '{mandate_context}'",
            rule_id="R2",
        )

    # R3 — scope
    scope = cs.get("scope", [])
    if request.action not in scope:
        return PolicyDecision(
            False,
            f"acción '{request.action}' no está en el scope del mandato {scope}",
            rule_id="R3",
        )

    # R4 — read_only
    constraints = cs.get("constraints", {}) or {}
    if constraints.get("readOnly") and not request.action.startswith("read:"):
        return PolicyDecision(
            False,
            f"mandato es read-only y la acción '{request.action}' no es de lectura",
            rule_id="R4",
        )

    # R5 — allowed_environments
    allowed_envs = constraints.get("allowedEnvironments")
    if allowed_envs and request.environment and request.environment not in allowed_envs:
        return PolicyDecision(
            False,
            f"environment '{request.environment}' no está en {allowed_envs}",
            rule_id="R5",
        )

    return PolicyDecision(True, "OK — acción dentro del mandato", rule_id="R0")


# ---------------------------------------------------------------------------
# revocación vía Bitstring Status List
# ---------------------------------------------------------------------------

def is_revoked(
    vc: dict[str, Any],
    issuer_public_jwk: dict,
    *,
    timeout: float = 5.0,
) -> tuple[bool, str]:
    """
    Comprueba la revocación contra la BitstringStatusListCredential del issuer.
    Devuelve (revoked, reason).
    """
    status = vc.get("credentialStatus")
    if not status:
        return False, "VC sin credentialStatus — no se puede revocar (asumimos válida)"

    if status.get("type") != "BitstringStatusListEntry":
        return False, f"status type {status.get('type')} no soportado en spike"

    list_url = status.get("statusListCredential")
    index = int(status.get("statusListIndex", -1))
    if not list_url or index < 0:
        return False, "credentialStatus mal formado"

    # Fetch del status list (es otra VC firmada por el issuer)
    try:
        response = httpx.get(list_url, timeout=timeout)
        response.raise_for_status()
        body = response.json()
    except Exception as e:
        # Política conservadora: si no puedo verificar revocación, deniego.
        return True, f"no se pudo descargar status list: {e}"

    list_jwt = body.get("credential")
    if not list_jwt:
        return True, "respuesta de status list sin 'credential'"

    # Verificamos firma del status list (el mismo issuer que el VC)
    try:
        list_payload = verify_jwt_with_jwk(list_jwt, issuer_public_jwk)
    except Exception as e:
        return True, f"firma del status list inválida: {e}"

    list_vc = list_payload.get("vc", {})
    encoded_list = list_vc.get("credentialSubject", {}).get("encodedList")
    if not encoded_list:
        return True, "status list sin encodedList"

    try:
        state = decode_bitstring(encoded_list, size_bits=DEFAULT_STATUS_LIST_SIZE_BITS)
        revoked = state.is_set(index)
    except Exception as e:
        return True, f"error decodificando bitstring: {e}"

    if revoked:
        return True, f"bit {index} del status list está a 1 (revocada)"
    return False, f"bit {index} del status list está a 0 (vigente)"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    # `2026-05-07T12:00:00Z` → datetime aware UTC
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
