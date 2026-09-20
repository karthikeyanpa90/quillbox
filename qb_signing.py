# -*- coding: utf-8 -*-
"""What a provider does to sign a delivery to OWL (round 137's scheme, round 140's provider side).

Deliberately not `from owl.core.identities import ...`. A provider is a different party from OWL; if the only
implementation of the signature lived in OWL's own source and every provider imported it, "the provider proved
this" would reduce to "OWL's code agreed with itself". Thirty lines against the documented message shape is the
whole point -- INTEGRATING.md describes it, and anyone else's provider would write these thirty lines too.

The message is "<unix timestamp>.<delivery id>." followed by the raw request body, so a replayed or re-timed
capture does not verify under a new id or time, and every byte a reader would recompute a digest from -- the
`about` note included -- is inside the signature.
"""
import base64
import json
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def new_keypair() -> tuple:
    """(private_b64, public_b64): raw 32-byte Ed25519 keys, base64. The provider keeps the first and gives OWL
    the second at connector registration; OWL never holds the first, so there is no shared secret to leak."""
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def sign(private_b64: str, ts: str, delivery_id: str, body: bytes) -> str:
    k = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    return base64.b64encode(k.sign(f"{ts}.{delivery_id}.".encode("utf-8") + body)).decode()


def deliver(client, sid: str, measure: str, body: dict, private_b64: str, timeout: float = 60.0):
    """One signed delivery. The body is serialised once and both signed and sent as those exact bytes -- never
    re-serialised, or the signature would cover something other than what OWL verifies."""
    raw = json.dumps(body).encode("utf-8")
    ts = str(int(time.time()))
    did = str(uuid.uuid4())
    return client.post(f"/v1/systems/{sid}/records/{measure}", content=raw, timeout=timeout,
                       headers={"content-type": "application/json", "x-owl-ts": ts,
                                "x-owl-delivery": did, "x-owl-signature": sign(private_b64, ts, did, raw)})
