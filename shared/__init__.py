"""
shared — librería común a issuer, verifier, agent y registry_ui.

Importa lo más usado para que los servicios puedan hacer:

    from shared import sign_jwt, KeyCustody, did_key_from_custody, ...
"""
from .jwt_utils import (
    sign_jwt,
    parse_jwt_unverified,
    verify_jwt_with_jwk,
    b64url_encode,
    b64url_decode,
    now_iso,
    now_ts,
    JWTParseError,
    JWTVerifyError,
)
from .key_custody import (
    KeyCustody,
    LocalFileCustody,
    VaultCustody,
    build_custody,
)
from .did_key import (
    did_key_from_public_jwk,
    did_key_from_custody,
    resolve_did_key,
    public_jwk_for_did_key,
)
from .did_web import (
    did_web_to_url,
    resolve_did_web,
    public_jwk_for_did_web,
    build_did_web_document,
)
from .credential import (
    MandateInput,
    MandateConstraints,
    issue_mandate_vc_jwt,
    verify_mandate_vc_jwt,
    parse_vc_jwt_header,
    MandateVerificationError,
    AGENT_MANDATE_CONTEXT_URL,
    VC_TYPE,
)
from .status_list import (
    StatusListState,
    encode_bitstring,
    decode_bitstring,
    issue_status_list_vc_jwt,
    DEFAULT_STATUS_LIST_SIZE_BITS,
)

__all__ = [
    # jwt_utils
    "sign_jwt", "parse_jwt_unverified", "verify_jwt_with_jwk",
    "b64url_encode", "b64url_decode", "now_iso", "now_ts",
    "JWTParseError", "JWTVerifyError",
    # key_custody
    "KeyCustody", "LocalFileCustody", "VaultCustody", "build_custody",
    # did_key / did_web
    "did_key_from_public_jwk", "did_key_from_custody", "resolve_did_key", "public_jwk_for_did_key",
    "did_web_to_url", "resolve_did_web", "public_jwk_for_did_web", "build_did_web_document",
    # credential
    "MandateInput", "MandateConstraints", "issue_mandate_vc_jwt", "verify_mandate_vc_jwt",
    "parse_vc_jwt_header", "MandateVerificationError", "AGENT_MANDATE_CONTEXT_URL", "VC_TYPE",
    # status_list
    "StatusListState", "encode_bitstring", "decode_bitstring",
    "issue_status_list_vc_jwt", "DEFAULT_STATUS_LIST_SIZE_BITS",
]
