"""Key management: every agent's identity is an Ed25519 key pair.

Why Ed25519?  It is fast, has small keys/signatures, and has no tricky
parameters to get wrong (unlike RSA padding or ECDSA nonces).  The private key
never leaves the agent that owns it; only the public half (as a JWK) is shared
with the authorization server.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def save_private_key(key: Ed25519PrivateKey, path: Path) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create the file owner-read/write only *before* writing the secret.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint: a stable, unique ID for a public key.

    Only the required members, sorted, no whitespace -- so two parties always
    compute the same hash for the same key.
    """
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode()).digest())


def public_jwk(key: Ed25519PrivateKey | Ed25519PublicKey) -> dict:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    jwk = jwt.algorithms.OKPAlgorithm.to_jwk(pub, as_dict=True)
    jwk = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"]}
    jwk["kid"] = jwk_thumbprint(jwk)
    jwk["alg"] = "EdDSA"
    jwk["use"] = "sig"
    return jwk


def public_key_from_jwk(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("only Ed25519 (OKP) keys are accepted")
    if "d" in jwk:
        # A JWK containing "d" is a *private* key. Never accept one over the wire.
        raise ValueError("JWK contains private key material")
    key = jwt.PyJWK({"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]}).key
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


def private_key_path(keys_dir: Path, agent_id: str) -> Path:
    return keys_dir / f"{agent_id}.key.pem"


def public_jwk_path(keys_dir: Path, agent_id: str) -> Path:
    return keys_dir / f"{agent_id}.jwk.json"


def bootstrap_keys(keys_dir: Path, agent_ids: list[str], overwrite: bool = False) -> None:
    """Generate a key pair for each agent (and the auth server).

    In production each agent would generate its own key on its own host (or in
    a KMS/HSM) and only send the public JWK for registration.
    """
    for agent_id in agent_ids:
        priv_path = private_key_path(keys_dir, agent_id)
        if priv_path.exists() and not overwrite:
            continue
        key = generate_private_key()
        save_private_key(key, priv_path)
        public_jwk_path(keys_dir, agent_id).write_text(json.dumps(public_jwk(key), indent=2))
