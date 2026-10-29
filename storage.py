"""Encrypted document store: every file under data/apps is AES-256-GCM encrypted at rest.

shortcut: the key lives in data/pki/storage.key; production keeps it in a KMS/HSM on NIC infrastructure.
"""
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATA = Path(os.environ.get("PRAMAAN_DATA", Path(__file__).parent / "data"))
MAGIC = b"PRAMAAN1"


def _key():
    p = DATA / "pki" / "storage.key"
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(AESGCM.generate_key(bit_length=256))
    return p.read_bytes()


def write(path, data: bytes):
    nonce = os.urandom(12)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(MAGIC + nonce + AESGCM(_key()).encrypt(nonce, data, None))


def read(path) -> bytes:
    raw = Path(path).read_bytes()
    if not raw.startswith(MAGIC):
        raise ValueError(f"{path} is not an encrypted Pramaan blob")
    return AESGCM(_key()).decrypt(raw[8:20], raw[20:], None)


def encrypt_in_place(path):
    raw = Path(path).read_bytes()
    if not raw.startswith(MAGIC):
        write(path, raw)
