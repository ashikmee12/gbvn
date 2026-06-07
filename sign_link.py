import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from urllib.parse import quote


def arg(name, default=""):
    prefix = f"--{name}="
    for item in sys.argv[1:]:
        if item.startswith(prefix):
            return item[len(prefix):]
    return default


site = arg("site", os.getenv("PUBLIC_BLOGGER_URL", "https://dl.animethic.xyz/"))
secret = arg("secret", os.getenv("LINK_SIGNING_SECRET", ""))
start = arg("start") or arg("codes")
ttl = int(arg("ttl", "0"))

if not site or not secret or not start:
    print("Usage: python Tools/sign_link.py --site=https://blog.example.com --secret=LONG_SECRET --start=1234_1235-1240")
    raise SystemExit(1)


def parse_post_codes(value):
    expression = re.sub(r"\s+", "", str(value or ""))
    if not expression or not re.match(r"^\d+(?:-\d+)?(?:_\d+(?:-\d+)?)*$", expression):
        raise ValueError("Use 1234, 1234-1267, 1245_1223_3421, or mixed underscore/range patterns.")
    for segment in expression.split("_"):
        if "-" in segment:
            start_raw, end_raw = segment.split("-", 1)
            if int(start_raw) > int(end_raw):
                raise ValueError(f"Invalid range {segment}.")
    return expression


def encode_secret_token(kind, payload, ttl_seconds=0):
    now = int(time.time())
    data = dict(payload)
    data["kind"] = kind
    data["created_at"] = now
    ttl_seconds = int(ttl_seconds or 0)
    if ttl_seconds > 0:
        data["expires_at"] = now + ttl_seconds
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encrypted = xor_bytes(raw, secret_token_stream(kind, len(raw)))
    body = base64.urlsafe_b64encode(encrypted).decode("ascii").rstrip("=")
    sig = secret_token_signature(kind, body)
    return f"atx1.{body}.{sig}"


def secret_token_signature(kind, body):
    payload = f"atx1|{kind}|{body}".encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def secret_token_stream(kind, length):
    key = secret.encode("utf-8")
    seed = f"atx-secret-token|{kind}|v1".encode("utf-8")
    blocks = []
    total = 0
    counter = 0
    while total < length:
        block = hmac.new(key, seed + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        blocks.append(block)
        total += len(block)
        counter += 1
    return b"".join(blocks)[:length]


def xor_bytes(value, stream):
    return bytes(left ^ right for left, right in zip(value, stream))


expression = parse_post_codes(start)
token = encode_secret_token("page", {"expression": expression}, ttl)
separator = "&" if "?" in site else "?"
print(f"{site}{separator}token={quote(token)}")
