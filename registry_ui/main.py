"""
registry_ui/main.py

Mini-UI de alta de agentes — H0 del spike.

Es la "pantalla del usuario humano de la organización" (delegador) que da
de alta un agente y dispara la emisión de la Mandate Credential.

Flujo del usuario:
  1. Abre http://localhost:8002/
  2. "Alta de agente" → formulario con agent_id, scope, contexto, validez,
     delegator_did, constraints
  3. Al enviar:
     a. Genera la clave Ed25519 del agente en el backend de custodia.
     b. Calcula su did:key.
     c. Llama a issuer:/admin/credential-offer con MandateInput.
     d. Persiste el alta y muestra al usuario el credential_offer
        para copiar al agente.
  4. Listado de agentes en /

NOTA ARQUITECTÓNICA:
La generación de la clave del agente desde el Registry UI es deliberada
en el spike: simula el caso "la organización provisiona la identidad del
agente y le entrega su clave". En modelos donde el agente genera su propia
clave y se "presenta" para registro, este flow cambiaría: la UI recibiría
el did:key del agente como input y solo crearía el offer.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from shared import (
    build_custody,
    did_key_from_custody,
    MandateInput,
    MandateConstraints,
    now_iso,
    now_ts,
)

from . import storage


load_dotenv()


ISSUER_BASE_URL = os.getenv("ISSUER_BASE_URL", "http://localhost:8000")
ORG_DID = os.getenv("ORG_DID", "did:web:localhost%3A8000")


@asynccontextmanager
async def lifespan(app: FastAPI):
    storage.init_db()
    print("[registry_ui] iniciado")
    yield


app = FastAPI(title="AgentTrust Registry UI", lifespan=lifespan)

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ---------------------------------------------------------------------------
# Páginas HTML
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    agents = storage.list_agents()
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "agents": agents, "org_did": ORG_DID},
    )


@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    # Defaults razonables para que la demo sea instantánea
    return templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "org_did": ORG_DID,
            "default_delegator": f"{ORG_DID}#supervisor-001",
            "default_scope": "read:incidents,execute:restart_service,execute:notify_stakeholders",
            "default_context": "incident-management",
            "default_valid_from": now_iso(),
            "default_valid_until": _iso_in_days(30),
            "default_environments": "prod",
            "default_max_ops": "100",
        },
    )


@app.post("/register")
async def register_submit(
    request: Request,
    agent_id: str = Form(...),
    delegator_did: str = Form(...),
    scope: str = Form(...),
    context: str = Form(...),
    valid_from: str = Form(...),
    valid_until: str = Form(...),
    allowed_environments: str = Form(""),
    max_ops_per_hour: str = Form(""),
    read_only: str = Form(""),
):
    """
    Procesa el formulario, crea la identidad del agente, llama al issuer
    y muestra el credential_offer resultante.
    """
    # 1) Generar / cargar la clave del agente y su did:key
    custody = build_custody(f"agent-{agent_id}")
    agent_did = did_key_from_custody(custody)

    # 2) Construir el MandateInput
    scope_list = [s.strip() for s in scope.split(",") if s.strip()]
    envs_list = [e.strip() for e in allowed_environments.split(",") if e.strip()] or None
    constraints = MandateConstraints(
        max_operations_per_hour=int(max_ops_per_hour) if max_ops_per_hour.strip() else None,
        read_only=read_only.lower() in {"true", "1", "on", "yes"},
        allowed_environments=envs_list,
    )
    mandate = MandateInput(
        agent_did=agent_did,
        delegator_did=delegator_did,
        scope=scope_list,
        context=context,
        valid_from=valid_from,
        valid_until=valid_until,
        constraints=constraints,
    )

    # 3) Pedir al issuer que genere el credential_offer
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                f"{ISSUER_BASE_URL}/admin/credential-offer",
                json={"mandate": mandate.model_dump()},
            )
            response.raise_for_status()
            offer_data = response.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Issuer no responde: {e}")

    # 4) Persistir
    storage.save_agent(
        agent_id=agent_id,
        agent_did=agent_did,
        organization_did=ORG_DID,
        delegator_did=delegator_did,
        mandate_json=mandate.model_dump(),
        offer_id=offer_data.get("offer_id"),
        credential_offer=offer_data.get("credential_offer"),
        created_at=now_ts(),
    )

    return RedirectResponse(url=f"/agents/{agent_id}", status_code=303)


@app.get("/agents/{agent_id}", response_class=HTMLResponse)
def agent_detail(agent_id: str, request: Request):
    agent = storage.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="agent not found")
    offer_uri = None
    if agent.get("offer_id"):
        offer_uri = f"{ISSUER_BASE_URL}/credential-offer/{agent['offer_id']}"
    return templates.TemplateResponse(
        "agent_detail.html",
        {"request": request, "agent": agent, "offer_uri": offer_uri},
    )


@app.post("/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str, request: Request):
    agent = storage.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="agent not found")
    if agent.get("revoked"):
        return RedirectResponse(url=f"/agents/{agent_id}?msg=ya_revocado", status_code=303)

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{ISSUER_BASE_URL}/admin/revoke",
                json={"agent_did": agent["agent_did"]},
            )
            resp.raise_for_status()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Issuer no responde: {e}")

    storage.mark_revoked(agent_id, now_ts())
    print(f"[registry_ui] Mandato de '{agent_id}' REVOCADO vía UI", flush=True)
    return RedirectResponse(url=f"/agents/{agent_id}?msg=revocado", status_code=303)


# ---------------------------------------------------------------------------
# API JSON (lo usa scripts/demo.py)
# ---------------------------------------------------------------------------

class ApiRegisterRequest(BaseModel):
    agent_id: str
    delegator_did: str
    scope: list[str]
    context: str
    valid_from: str
    valid_until: str
    allowed_environments: list[str] | None = None
    max_operations_per_hour: int | None = None
    read_only: bool = False


@app.post("/api/agents")
def api_register(req: ApiRegisterRequest):
    custody = build_custody(f"agent-{req.agent_id}")
    agent_did = did_key_from_custody(custody)

    mandate = MandateInput(
        agent_did=agent_did,
        delegator_did=req.delegator_did,
        scope=req.scope,
        context=req.context,
        valid_from=req.valid_from,
        valid_until=req.valid_until,
        constraints=MandateConstraints(
            max_operations_per_hour=req.max_operations_per_hour,
            read_only=req.read_only,
            allowed_environments=req.allowed_environments,
        ),
    )

    with httpx.Client(timeout=10.0) as client:
        response = client.post(
            f"{ISSUER_BASE_URL}/admin/credential-offer",
            json={"mandate": mandate.model_dump()},
        )
        response.raise_for_status()
        offer_data = response.json()

    storage.save_agent(
        agent_id=req.agent_id,
        agent_did=agent_did,
        organization_did=ORG_DID,
        delegator_did=req.delegator_did,
        mandate_json=mandate.model_dump(),
        offer_id=offer_data.get("offer_id"),
        credential_offer=offer_data.get("credential_offer"),
        created_at=now_ts(),
    )

    return {
        "agent_id": req.agent_id,
        "agent_did": agent_did,
        "credential_offer_uri": offer_data.get("credential_offer_uri"),
        "credential_offer": offer_data.get("credential_offer"),
    }


@app.get("/api/agents")
def api_list():
    return storage.list_agents()


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _iso_in_days(days: int) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(tz=timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
