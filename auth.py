"""Sign-in: PBKDF2-hashed passwords and an HMAC-signed, HttpOnly session cookie.

The role and user every endpoint sees come only from a verified session, never from the browser.
shortcut: users live in data/users.json; production signs in through the AICTE portal's SSO (Keycloak/OIDC).
"""
import base64
import hashlib
import hmac
import json
import os
import time

import storage

COOKIE = "pramaan_session"
TTL = 8 * 3600  # one working day
ITERATIONS = 200_000


def _key():
    p = storage.DATA / "pki" / "session.key"
    if not p.exists():
        p.write_bytes(os.urandom(32))
    return p.read_bytes()


def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    return salt.hex(), hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS).hex()


def users():
    return json.loads((storage.DATA / "users.json").read_text())


def check(username, password):
    u = users().get(username)
    if not u:
        hash_password(password)  # same work for unknown users, so timing does not reveal who exists
        return None
    _, h = hash_password(password, bytes.fromhex(u["salt"]))
    return {"username": username, "role": u["role"], "name": u["name"]} if hmac.compare_digest(h, u["hash"]) else None


def issue(user):
    body = base64.urlsafe_b64encode(json.dumps({"u": user["username"], "exp": int(time.time()) + TTL}).encode()).decode()
    return body + "." + hmac.new(_key(), body.encode(), hashlib.sha256).hexdigest()


def read(token):
    """The signed-in user for a cookie value, or None if it is missing, forged or expired."""
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(sig, hmac.new(_key(), body.encode(), hashlib.sha256).hexdigest()):
        return None
    data = json.loads(base64.urlsafe_b64decode(body))
    u = users().get(data["u"])
    if data["exp"] < time.time() or not u:
        return None
    return {"username": data["u"], "role": u["role"], "name": u["name"]}
