import base64
import hashlib
import hmac
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _derive_aes_key() -> bytes:
    raw_key = os.getenv("NETRCA_AES_KEY", "netrca-dev-aes-key")
    return hashlib.sha256(raw_key.encode("utf-8")).digest()


def encrypt_log_data(plaintext: str) -> str:
    aesgcm = AESGCM(_derive_aes_key())
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_log_data(ciphertext: str) -> str:
    try:
        payload = base64.b64decode(ciphertext.encode("utf-8"))
        nonce, encrypted = payload[:12], payload[12:]
        aesgcm = AESGCM(_derive_aes_key())
        return aesgcm.decrypt(nonce, encrypted, None).decode("utf-8")
    except Exception:
        # Legacy plaintext rows remain readable during the prototype-to-MVP upgrade.
        return ciphertext


def sha512_hash(content: str) -> str:
    return hashlib.sha512(content.encode("utf-8")).hexdigest()


def _hmac_secret() -> str:
    return os.getenv("NETRCA_HMAC_SECRET", "")


def hmac_enforced() -> bool:
    return bool(_hmac_secret())


def build_hmac_signature(body: bytes, timestamp: str) -> str:
    secret = _hmac_secret()
    if not secret:
        return ""
    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha512)
    mac.update(timestamp.encode("utf-8"))
    mac.update(b".")
    mac.update(body)
    return mac.hexdigest()


def verify_hmac_signature(body: bytes, timestamp: str | None, signature: str | None) -> bool:
    secret = _hmac_secret()
    if not secret:
        return True
    if not timestamp or not signature:
        return False
    normalized_signature = signature.removeprefix("sha512=")
    expected = build_hmac_signature(body, timestamp)
    return hmac.compare_digest(normalized_signature, expected)


def verify_digital_signature(
    message: bytes,
    signature_b64: str | None,
    public_key_pem: str | None,
) -> bool:
    if not signature_b64 or not public_key_pem:
        return False

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        public_key.verify(
            base64.b64decode(signature_b64),
            message,
            padding.PKCS1v15(),
            hashes.SHA512(),
        )
        return True
    except Exception:
        return False


def tls_configuration() -> dict[str, Any]:
    cert_file = os.getenv("NETRCA_TLS_CERT_FILE")
    key_file = os.getenv("NETRCA_TLS_KEY_FILE")
    return {
        "tls_ready": bool(cert_file and key_file),
        "cert_file_configured": bool(cert_file),
        "key_file_configured": bool(key_file),
        "guidance": "Run uvicorn with --ssl-certfile and --ssl-keyfile in production.",
    }
