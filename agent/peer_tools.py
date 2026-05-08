"""
agent/peer_tools.py

Acciones que Agent2 puede ejecutar en nombre de otro agente autorizado.
Equivalente a tools.py pero desde la perspectiva del agente receptor (servidor A2A).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class PeerTool:
    action: str
    description: str
    run: Callable[..., dict[str, Any]]


def _database_backup(database: str = "main", mode: str = "incremental") -> dict:
    return {
        "tool": "database_backup",
        "database": database,
        "mode": mode,
        "backup_id": f"bkp-{database}-20260508",
        "result": f"backup {mode} de '{database}' completado (simulado)",
    }


def _read_system_metrics(service: str = "all") -> dict:
    return {
        "tool": "read_system_metrics",
        "service": service,
        "cpu_pct": 42.1,
        "mem_pct": 67.3,
        "latency_p99_ms": 120,
        "result": f"métricas de '{service}' obtenidas (simulado)",
    }


def _scale_service(service: str, replicas: int = 2) -> dict:
    return {
        "tool": "scale_service",
        "service": service,
        "replicas": replicas,
        "result": f"servicio '{service}' escalado a {replicas} réplicas (simulado)",
    }


PEER_TOOLS: dict[str, PeerTool] = {
    "execute:database_backup": PeerTool(
        action="execute:database_backup",
        description="Ejecuta un backup de base de datos. Requiere mandato con execute:database_backup.",
        run=_database_backup,
    ),
    "read:system_metrics": PeerTool(
        action="read:system_metrics",
        description="Lee métricas del sistema.",
        run=_read_system_metrics,
    ),
    "execute:scale_service": PeerTool(
        action="execute:scale_service",
        description="Escala un servicio. Requiere mandato con execute:scale_service.",
        run=_scale_service,
    ),
}


def get_peer_tool(action: str) -> PeerTool:
    if action not in PEER_TOOLS:
        raise KeyError(f"Acción peer desconocida: '{action}'. Disponibles: {list(PEER_TOOLS)}")
    return PEER_TOOLS[action]
