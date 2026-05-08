#!/usr/bin/env bash
# scripts/init_vault.sh
#
# Inicializa HashiCorp Vault Transit engine y crea la clave Ed25519
# de la organización emisora.
#
# Prerrequisito: tener Vault corriendo. Ejemplo dev mode:
#
#   docker run -d --name vault-spike \
#     -p 8200:8200 \
#     -e 'VAULT_DEV_ROOT_TOKEN_ID=root-token-spike' \
#     hashicorp/vault:latest
#
# Luego: bash scripts/init_vault.sh

set -euo pipefail

: "${VAULT_ADDR:=http://localhost:8200}"
: "${VAULT_TOKEN:=root-token-spike}"
: "${VAULT_TRANSIT_MOUNT:=transit}"

export VAULT_ADDR VAULT_TOKEN

echo "=== AgentTrust — Vault Transit setup ==="
echo "  VAULT_ADDR   = $VAULT_ADDR"
echo "  MOUNT POINT  = $VAULT_TRANSIT_MOUNT"
echo

# Detecta si tenemos el CLI de vault o usamos curl directo.
if command -v vault >/dev/null 2>&1; then
    USE_CLI=1
else
    USE_CLI=0
    echo "(vault CLI no encontrado — uso curl directo)"
fi

http_call() {
    local method="$1"
    local path="$2"
    local data="${3:-}"
    if [ -n "$data" ]; then
        curl -fsS -X "$method" -H "X-Vault-Token: $VAULT_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$VAULT_ADDR/v1/$path"
    else
        curl -fsS -X "$method" -H "X-Vault-Token: $VAULT_TOKEN" \
            "$VAULT_ADDR/v1/$path"
    fi
}

# 1) Habilitar el motor transit (idempotente: si ya existe, ignora el error)
echo "[1/3] Habilitando motor transit en $VAULT_TRANSIT_MOUNT..."
if [ "$USE_CLI" -eq 1 ]; then
    vault secrets enable -path="$VAULT_TRANSIT_MOUNT" transit 2>/dev/null \
        || echo "  (transit ya estaba habilitado)"
else
    http_call POST "sys/mounts/$VAULT_TRANSIT_MOUNT" '{"type":"transit"}' >/dev/null 2>&1 \
        || echo "  (transit ya estaba habilitado)"
fi

# 2) Crear clave Ed25519 de la organización
echo "[2/3] Creando clave Ed25519 'org-issuer'..."
if [ "$USE_CLI" -eq 1 ]; then
    vault write -f "$VAULT_TRANSIT_MOUNT/keys/org-issuer" type=ed25519 2>/dev/null \
        || echo "  (clave ya existía)"
else
    http_call POST "$VAULT_TRANSIT_MOUNT/keys/org-issuer" '{"type":"ed25519"}' \
        || echo "  (clave ya existía)"
fi

# 3) Verificar
echo "[3/3] Verificando..."
if [ "$USE_CLI" -eq 1 ]; then
    vault read "$VAULT_TRANSIT_MOUNT/keys/org-issuer" | head -20
else
    http_call GET "$VAULT_TRANSIT_MOUNT/keys/org-issuer" | python3 -m json.tool | head -20
fi

echo
echo "✓ Vault listo. Configura .env con:"
echo "    KEY_CUSTODY_BACKEND=vault"
echo "    VAULT_ADDR=$VAULT_ADDR"
echo "    VAULT_TOKEN=$VAULT_TOKEN"
echo "    VAULT_TRANSIT_MOUNT=$VAULT_TRANSIT_MOUNT"
