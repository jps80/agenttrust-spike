"""
agent/tools.py

Tools de ejemplo para validar el patrón "el agente solo actúa con mandato vigente".

Cada tool tiene:
  - `name`: identificador legible
  - `action`: verbo:recurso del scope OID4VP (ej. "execute:restart_service")
  - `context`: sistema/proceso al que pertenece (ej. "incident-management")
  - `run(**kwargs)`: implementación dummy

El runtime envuelve cada llamada en una presentación OID4VP: el agente
presenta su Mandate Credential, el verifier evalúa, y solo si autoriza
se invoca `run()`. Si no autoriza, la tool no se ejecuta.

En producción esto es la capa que se inyecta en LangChain / AutoGen como
middleware antes del tool-calling. El agente conserva la decisión de "qué
tool llamar" (LLM); el verifier conserva la decisión de "puede esta
identidad ejecutar este tool" (mandato).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class Tool:
    name: str
    description: str
    action: str        # debe encajar con el scope del mandato
    context: str       # debe encajar con el context del mandato
    run: Callable[..., dict[str, Any]]
    environment: str | None = None  # opcional, para R5 del policy engine


# ---------------------------------------------------------------------------
# implementaciones dummy
# ---------------------------------------------------------------------------

def _read_incident(incident_id: str) -> dict:
    return {
        "tool": "read_incident",
        "incident_id": incident_id,
        "status": "OPEN",
        "severity": "high",
        "summary": f"Mock data para {incident_id}",
    }


def _restart_service(service_name: str) -> dict:
    return {
        "tool": "restart_service",
        "service_name": service_name,
        "result": "restarted (simulated)",
    }


def _escalate_to_human(incident_id: str, reason: str) -> dict:
    return {
        "tool": "escalate_to_human",
        "incident_id": incident_id,
        "reason": reason,
        "result": "escalation queued (simulated)",
    }


def _notify_stakeholders(incident_id: str, message: str) -> dict:
    return {
        "tool": "notify_stakeholders",
        "incident_id": incident_id,
        "message": message,
        "result": "notification sent (simulated)",
    }


# ---------------------------------------------------------------------------
# registro
# ---------------------------------------------------------------------------

DEFAULT_TOOLS: dict[str, Tool] = {
    "read_incident": Tool(
        name="read_incident",
        description="Lee el detalle de una incidencia del sistema de tickets.",
        action="read:incidents",
        context="incident-management",
        environment="prod",
        run=_read_incident,
    ),
    "restart_service": Tool(
        name="restart_service",
        description="Reinicia un servicio en producción. Acción de alto riesgo.",
        action="execute:restart_service",
        context="incident-management",
        environment="prod",
        run=_restart_service,
    ),
    "escalate_to_human": Tool(
        name="escalate_to_human",
        description="Escala una incidencia a un humano de guardia.",
        action="execute:escalate_to_human",
        context="incident-management",
        environment="prod",
        run=_escalate_to_human,
    ),
    "notify_stakeholders": Tool(
        name="notify_stakeholders",
        description="Envía notificaciones a stakeholders por email/Slack.",
        action="execute:notify_stakeholders",
        context="incident-management",
        environment="prod",
        run=_notify_stakeholders,
    ),
}


def get_tool(name: str) -> Tool:
    if name not in DEFAULT_TOOLS:
        raise KeyError(f"Tool desconocida: {name}. Disponibles: {list(DEFAULT_TOOLS)}")
    return DEFAULT_TOOLS[name]
