#!/usr/bin/env python3
"""A dependency-free, authenticated web control panel for Garage S3.

The panel is intended for a trusted administrative network and listens on
loopback by default. Sign-in sets an HMAC-signed, expiring session cookie; the
password is compared in constant time and never stored in the cookie.
Credentials and the Garage admin token come from the environment, never from
the client.

The application uses only the Python standard library. It can run directly
from this source tree or be installed as a Python package.
"""

from __future__ import annotations

import base64
import datetime
import secrets
import time
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sysconfig
import threading
import xml.etree.ElementTree as ElementTree
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}

GARAGE_ADMIN = os.environ.get("GARAGE_ADMIN_URL", "http://127.0.0.1:3903").rstrip("/")
GARAGE_TOKEN = os.environ.get("GARAGE_ADMIN_TOKEN", "")
PANEL_USER = os.environ.get("PANEL_USER", "admin")
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")
LISTEN_HOST = os.environ.get("PANEL_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("PANEL_PORT", "8088"))

# Optional backup-age reporting. Garage's admin API knows object counts and
# sizes but not timestamps, so answering "how fresh is this backup?" needs the
# S3 API and a read-capable key. Leave the credentials unset and the panel
# simply omits the columns instead of failing.
S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "http://127.0.0.1:3900").rstrip("/")
S3_REGION = os.environ.get("S3_REGION", "us-east-1")
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY", "")
S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY", "")
# The panel's reporting key is normally read-only. File manipulation uses a
# separate, explicitly configured read/write key so the monitoring path does
# not silently gain object mutation rights.
S3_BROWSER_ACCESS_KEY = os.environ.get("S3_BROWSER_ACCESS_KEY", "")
S3_BROWSER_SECRET_KEY = os.environ.get("S3_BROWSER_SECRET_KEY", "")
S3_BROWSER_MAX_OBJECTS = max(
    1, int(os.environ.get("PANEL_BROWSER_MAX_OBJECTS", "500"))
)
S3_BROWSER_UPLOAD_MAX_BYTES = max(
    1, int(os.environ.get("PANEL_BROWSER_UPLOAD_MAX_BYTES", "52428800"))
)
# Comma-separated bucket names to age-check. Empty means every bucket the key
# can read — point it at just the backup buckets to keep the page quick.
BACKUP_BUCKETS = [
    name.strip()
    for name in os.environ.get("BACKUP_BUCKETS", "").split(",")
    if name.strip()
]
# Finding the newest and oldest object means scanning the listing, so cap it.
BACKUP_MAX_OBJECTS = max(1, int(os.environ.get("BACKUP_MAX_OBJECTS", "5000")))
BACKUP_AGE_ENABLED = bool(S3_ACCESS_KEY and S3_SECRET_KEY)
LATEST_OBJECTS = max(1, int(os.environ.get("PANEL_LATEST_OBJECTS", "5")))
# Six months is a useful default for a private admin panel. Set a persistent
# PANEL_SESSION_SECRET as well if sessions should survive panel restarts.
SESSION_HOURS = max(1, int(os.environ.get("PANEL_SESSION_HOURS", "4320")))
# Persisted so sign-ins survive panel restarts; PANEL_SESSION_SECRET overrides.
SESSION_SECRET_FILE = Path(
    os.environ.get(
        "PANEL_SESSION_SECRET_FILE", "/var/lib/garage-panel/session-secret"
    )
)

def _load_or_create_session_secret() -> str:
    """Persist a random session secret so sign-ins survive panel restarts.

    Without this, every restart silently signs everyone out. The file is
    created with restrictive permissions; PANEL_SESSION_SECRET overrides it
    entirely for deployments that manage the value themselves.
    """
    try:
        return SESSION_SECRET_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        pass
    except OSError as error:
        print(f"session secret unreadable: {error}", flush=True)
        return secrets.token_hex(32)
    secret = secrets.token_hex(32)
    try:
        SESSION_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        SESSION_SECRET_FILE.write_text(secret + "\n", encoding="utf-8")
        SESSION_SECRET_FILE.chmod(0o600)
    except OSError as error:
        print(f"session secret not persisted: {error}", flush=True)
    return secret


# Remember-me sessions outlive the default window; 0 disables the checkbox.
REMEMBER_ME_DAYS = max(0, int(os.environ.get("PANEL_REMEMBER_ME_DAYS", "30")))
SESSION_SECRET = (
    os.environ.get("PANEL_SESSION_SECRET", "")
    or _load_or_create_session_secret()
)
COOKIE_NAME = "garage_panel_session"
# How buckets are reached from outside, so the panel can show a usable path per
# bucket. This deployment intentionally uses path-style URLs only.
S3_PUBLIC_ENDPOINT = os.environ.get("S3_PUBLIC_ENDPOINT", "").rstrip("/")
# Sign-ins are appended here so "who used this and when" is answerable.
AUDIT_LOG = os.environ.get("PANEL_AUDIT_LOG", "/var/lib/garage-panel/signins.log")
# Mutating panel actions are recorded separately from authentication events.
ACTIVITY_LOG = os.environ.get(
    "PANEL_ACTIVITY_LOG", "/var/lib/garage-panel/activity.log"
)
# API keys for scripts. Only a hash is stored, so a lost token cannot be
# recovered — issue a new one instead.
API_KEY_STORE = os.environ.get("PANEL_API_KEYS", "/var/lib/garage-panel/apikeys.json")
# S3 secrets are encrypted with a key derived from PANEL_PASSWORD and stored
# here so a deliberate password re-entry can reveal them later. Secrets from
# keys created before this store existed cannot be recovered from Garage.
KEY_SECRET_STORE = os.environ.get(
    "PANEL_KEY_SECRETS", "/var/lib/garage-panel/key-secrets.json"
)
ARCHIVE_STORE = os.environ.get(
    "PANEL_ARCHIVED_BUCKETS", "/var/lib/garage-panel/archived-buckets.json"
)
# Friendly display names are keyed by Garage bucket ID so they survive alias
# changes while the underlying bucket remains the same.
BUCKET_NAME_STORE = os.environ.get(
    "PANEL_BUCKET_NAMES", "/var/lib/garage-panel/bucket-names.json"
)
ARCHIVE_DAYS = max(1, int(os.environ.get("PANEL_BUCKET_ARCHIVE_DAYS", "60")))
PURGE_MAX_OBJECTS = max(
    1, int(os.environ.get("PANEL_PURGE_MAX_OBJECTS", "1000000"))
)
# Optional dedicated delete credentials. If absent, purge uses the owner/write
# key Garage already grants on the bucket, retrieved only inside the panel.
DELETE_ACCESS_KEY = os.environ.get("S3_DELETE_ACCESS_KEY", "")
DELETE_SECRET_KEY = os.environ.get("S3_DELETE_SECRET_KEY", "")
SOURCE_STATIC_DIR = Path(__file__).resolve().with_name("static")
INSTALLED_STATIC_DIR = (
    Path(sysconfig.get_path("data")) / "share" / "garage-admin-panel" / "static"
)
STATIC_DIR = os.environ.get(
    "PANEL_STATIC_DIR",
    str(SOURCE_STATIC_DIR if SOURCE_STATIC_DIR.is_dir() else INSTALLED_STATIC_DIR),
)
ARCHIVE_LOCK = threading.RLock()
BUCKET_NAME_LOCK = threading.RLock()

# Optional operational integrations. They are disabled unless explicitly
# enabled in garage-panel.env; the dashboard must remain useful without them.
SYSTEMCTL = os.environ.get("PANEL_SYSTEMCTL", "/bin/systemctl")
CLOUDFLARED_ENABLED = _env_flag("PANEL_CLOUDFLARED_ENABLED")
CLOUDFLARED_BIN = os.environ.get(
    "PANEL_CLOUDFLARED_BIN", "/usr/local/bin/cloudflared"
)
CLOUDFLARED_SERVICE = os.environ.get(
    "PANEL_CLOUDFLARED_SERVICE", "garage-cloudflared.service"
)
CLOUDFLARED_UPDATE_SERVICE = os.environ.get(
    "PANEL_CLOUDFLARED_UPDATE_SERVICE", "garage-cloudflared-update.service"
)
CLOUDFLARED_TIMEOUT = max(
    30, int(os.environ.get("PANEL_CLOUDFLARED_TIMEOUT", "600"))
)
CLOUDFLARED_LOCK = threading.Lock()

RESTIC_ENABLED = _env_flag("PANEL_RESTIC_ENABLED")
RESTIC_BIN = os.environ.get("PANEL_RESTIC_BIN", "/usr/local/bin/restic")
RESTIC_PASSWORD_FILE = os.environ.get(
    "PANEL_RESTIC_PASSWORD_FILE", "/etc/restic/archive.password"
)
RESTIC_PASSWORD_STORE = os.environ.get(
    "PANEL_RESTIC_PASSWORDS", "/var/lib/garage-panel/restic-passwords.json"
)
RESTIC_CHECK_TIMEOUT = max(
    30, int(os.environ.get("PANEL_RESTIC_CHECK_TIMEOUT", "600"))
)
RESTIC_CHECK_STORE = os.environ.get(
    "PANEL_RESTIC_CHECKS", "/var/lib/garage-panel/restic-checks.json"
)
RESTIC_LOCK = threading.Lock()
PANEL_AUTO_GRANT_READ = _env_flag("PANEL_AUTO_GRANT_READ", True)


class GarageError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def garage(path: str, method: str = "GET", payload: dict | list | None = None):
    """Call the Garage admin API. Errors are surfaced verbatim: a panel that
    hides why Garage refused something is worse than no panel."""
    body = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        f"{GARAGE_ADMIN}{path}",
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {GARAGE_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:400]
        try:
            detail = json.loads(detail).get("message", detail)
        except ValueError:
            pass
        raise GarageError(error.code, detail) from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise GarageError(502, f"Garage unreachable: {error}") from error


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


def _s3_request(
    bucket: str,
    query: dict,
    method: str = "GET",
    body: bytes = b"",
    access_key: str | None = None,
    secret_key: str | None = None,
    object_key: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    """Signed (SigV4) path-style request against the S3 API."""
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    host = urllib.parse.urlparse(S3_ENDPOINT).netloc
    canonical_uri = "/" + urllib.parse.quote(bucket, safe="")
    if object_key is not None:
        canonical_uri += "/" + urllib.parse.quote(object_key, safe="/~")
    canonical_query = urllib.parse.urlencode(sorted(query.items()))
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_header_values = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    content_md5 = ""
    if body:
        content_md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
        canonical_header_values["content-md5"] = content_md5
    for name, value in (extra_headers or {}).items():
        canonical_header_values[name.lower().strip()] = " ".join(
            str(value).strip().split()
        )
    canonical_headers = "".join(
        f"{name}:{canonical_header_values[name]}\n"
        for name in sorted(canonical_header_values)
    )
    signed_headers = ";".join(sorted(canonical_header_values))
    canonical_request = "\n".join(
        [method, canonical_uri, canonical_query, canonical_headers,
         signed_headers, payload_hash]
    )
    scope = f"{date_stamp}/{S3_REGION}/s3/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope,
         hashlib.sha256(canonical_request.encode()).hexdigest()]
    )
    access_key = access_key or S3_ACCESS_KEY
    secret_key = secret_key or S3_SECRET_KEY
    if not access_key or not secret_key:
        raise GarageError(503, "No S3 credentials are configured for this operation.")
    key = _sign(("AWS4" + secret_key).encode(), date_stamp)
    key = _sign(key, S3_REGION)
    key = _sign(key, "s3")
    signing_key = _sign(key, "aws4_request")
    signature = hmac.new(
        signing_key, string_to_sign.encode(), hashlib.sha256
    ).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    request_headers = {
        "Authorization": authorization,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
        "Host": host,
    }
    if content_md5:
        request_headers["Content-MD5"] = content_md5
    for name, value in (extra_headers or {}).items():
        request_headers[name] = value
    request = urllib.request.Request(
        f"{S3_ENDPOINT}{canonical_uri}?{canonical_query}",
        data=body or None,
        method=method,
        headers=request_headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", "replace")
        try:
            root = ElementTree.fromstring(raw)
            fields = {
                (item.tag.rsplit("}", 1)[-1]): (item.text or "").strip()
                for item in root.iter()
                if item.text
            }
            code = fields.get("Code")
            message = fields.get("Message")
            detail = (
                f"S3 {code}: {message}"
                if code and message
                else code or message or "S3 request failed."
            )
        except ElementTree.ParseError:
            detail = raw.strip()[:200] or "S3 request failed."
        raise GarageError(error.code, detail)
    except (urllib.error.URLError, TimeoutError) as error:
        raise GarageError(502, f"S3 endpoint unreachable: {error}")


def _bucket_objects_error(error: GarageError) -> str:
    if error.status == 403 and error.message.startswith("S3 AccessDenied"):
        return "S3 access denied; grant the panel key read access to this bucket."
    return error.message


def bucket_objects(bucket: str) -> dict:
    """Return backup ages and the newest listed objects for a bucket.

    S3 listings are lexicographic rather than chronological, so finding the
    newest objects requires scanning the listing. The existing safety cap is
    shared by the age and recent-file views, and the response says when that
    cap was reached.
    """
    namespace = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    newest = oldest = None
    latest = []
    restic_markers = set()
    scanned = 0
    token = None
    truncated = False
    while True:
        query = {"list-type": "2", "max-keys": "1000"}
        if token:
            query["continuation-token"] = token
        root = ElementTree.fromstring(_s3_request(bucket, query))
        for item in root.findall(f"{namespace}Contents"):
            key = item.findtext(f"{namespace}Key") or ""
            if key == "config":
                restic_markers.add("config")
            elif key.startswith("keys/"):
                restic_markers.add("keys")
            elif key.startswith("index/"):
                restic_markers.add("index")
            elif key.startswith("snapshots/"):
                restic_markers.add("snapshots")
            elif key.startswith("data/"):
                restic_markers.add("data")
            stamp = item.findtext(f"{namespace}LastModified")
            scanned += 1
            if stamp:
                if newest is None or stamp > newest:
                    newest = stamp
                if oldest is None or stamp < oldest:
                    oldest = stamp
            try:
                size = int(item.findtext(f"{namespace}Size") or 0)
            except ValueError:
                size = None
            latest.append({"key": key, "size": size, "modified": stamp})
        if scanned >= BACKUP_MAX_OBJECTS:
            truncated = root.findtext(f"{namespace}IsTruncated") == "true"
            break
        if root.findtext(f"{namespace}IsTruncated") != "true":
            break
        token = root.findtext(f"{namespace}NextContinuationToken")
        if not token:
            break
    latest.sort(key=lambda item: item.get("modified") or "", reverse=True)
    return {
        "newest": newest,
        "oldest": oldest,
        "latest": latest[:LATEST_OBJECTS],
        "scanned": scanned,
        "truncated": truncated,
        "resticStyle": {
            "detected": {"config", "keys", "index", "snapshots"}.issubset(
                restic_markers
            ),
            "markers": sorted(restic_markers),
        },
    }


def browser_read_credentials() -> tuple[str, str]:
    if S3_BROWSER_ACCESS_KEY and S3_BROWSER_SECRET_KEY:
        return S3_BROWSER_ACCESS_KEY, S3_BROWSER_SECRET_KEY
    if S3_ACCESS_KEY and S3_SECRET_KEY:
        return S3_ACCESS_KEY, S3_SECRET_KEY
    raise GarageError(
        503,
        "Bucket browsing is disabled; configure S3_ACCESS_KEY and S3_SECRET_KEY.",
    )


def browser_write_credentials() -> tuple[str, str]:
    if S3_BROWSER_ACCESS_KEY and S3_BROWSER_SECRET_KEY:
        return S3_BROWSER_ACCESS_KEY, S3_BROWSER_SECRET_KEY
    raise GarageError(
        503,
        "File changes are disabled; configure a separate read/write S3_BROWSER_ACCESS_KEY and S3_BROWSER_SECRET_KEY.",
    )


def require_active_bucket(name: str) -> str:
    name = str(name or "").strip()
    if not name:
        raise GarageError(400, "A bucket name is required.")
    with ARCHIVE_LOCK:
        archived = _load_archived_buckets()
    archived_ids = {record.get("bucketId") for record in archived}
    archived_names = {record.get("name") for record in archived}
    for bucket in garage("/v2/ListBuckets"):
        aliases = bucket.get("globalAliases") or []
        if name in aliases and bucket.get("id") not in archived_ids and name not in archived_names:
            return name
    raise GarageError(404, "No active bucket has that exact name.")


def _checked_object_key(value: str, label: str = "An object key") -> str:
    key = str(value or "")
    if not key or "\x00" in key or len(key) > 1024:
        raise GarageError(400, f"{label} is missing or too long.")
    return key


def browser_list_objects(bucket: str, prefix: str = "", continuation: str = "") -> dict:
    """List one folder level for the basic authenticated bucket browser."""
    bucket = require_active_bucket(bucket)
    prefix = str(prefix or "")
    if len(prefix) > 1024 or "\x00" in prefix:
        raise GarageError(400, "The folder prefix is invalid.")
    access_key, secret_key = browser_read_credentials()
    query = {
        "list-type": "2",
        "delimiter": "/",
        "max-keys": str(S3_BROWSER_MAX_OBJECTS),
    }
    if prefix:
        query["prefix"] = prefix
    if continuation:
        query["continuation-token"] = continuation
    namespace = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    try:
        root = ElementTree.fromstring(
            _s3_request(
                bucket,
                query,
                access_key=access_key,
                secret_key=secret_key,
            )
        )
    except ElementTree.ParseError as error:
        raise GarageError(502, f"S3 returned invalid listing XML: {error}") from error
    objects = []
    for item in root.findall(f"{namespace}Contents"):
        key = item.findtext(f"{namespace}Key") or ""
        modified = item.findtext(f"{namespace}LastModified")
        try:
            size = int(item.findtext(f"{namespace}Size") or 0)
        except ValueError:
            size = None
        objects.append({"key": key, "size": size, "modified": modified})
    prefixes = [
        item.text or ""
        for item in root.findall(f"{namespace}CommonPrefixes/{namespace}Prefix")
        if item.text
    ]
    return {
        "bucket": bucket,
        "prefix": prefix,
        "objects": objects,
        "prefixes": prefixes,
        "truncated": root.findtext(f"{namespace}IsTruncated") == "true",
        "nextToken": root.findtext(f"{namespace}NextContinuationToken"),
        "writeEnabled": bool(S3_BROWSER_ACCESS_KEY and S3_BROWSER_SECRET_KEY),
        "maxUploadBytes": S3_BROWSER_UPLOAD_MAX_BYTES,
    }


def browser_upload(bucket: str, key: str, body: bytes, content_type: str = "") -> None:
    bucket = require_active_bucket(bucket)
    key = _checked_object_key(key)
    if len(body) > S3_BROWSER_UPLOAD_MAX_BYTES:
        raise GarageError(
            413,
            f"Upload exceeds the {human_bytes(S3_BROWSER_UPLOAD_MAX_BYTES)} limit.",
        )
    access_key, secret_key = browser_write_credentials()
    headers = {}
    if content_type:
        headers["content-type"] = " ".join(str(content_type).split())[:200]
    _s3_request(
        bucket,
        {},
        method="PUT",
        body=body,
        access_key=access_key,
        secret_key=secret_key,
        object_key=key,
        extra_headers=headers,
    )


def browser_delete(bucket: str, key: str) -> None:
    bucket = require_active_bucket(bucket)
    key = _checked_object_key(key)
    access_key, secret_key = browser_write_credentials()
    _s3_request(
        bucket,
        {},
        method="DELETE",
        access_key=access_key,
        secret_key=secret_key,
        object_key=key,
    )


def browser_rename(bucket: str, key: str, new_key: str) -> None:
    bucket = require_active_bucket(bucket)
    key = _checked_object_key(key)
    new_key = _checked_object_key(new_key, "The new object key")
    if key == new_key:
        raise GarageError(400, "The new object key must be different.")
    access_key, secret_key = browser_write_credentials()
    copy_source = "/" + urllib.parse.quote(bucket, safe="") + "/" + urllib.parse.quote(key, safe="/~")
    _s3_request(
        bucket,
        {},
        method="PUT",
        access_key=access_key,
        secret_key=secret_key,
        object_key=new_key,
        extra_headers={"x-amz-copy-source": copy_source},
    )
    _s3_request(
        bucket,
        {},
        method="DELETE",
        access_key=access_key,
        secret_key=secret_key,
        object_key=key,
    )


def s3_object_keys(bucket: str, access_key: str, secret_key: str) -> list[str]:
    """List every object key for a purge, with a safety ceiling."""
    namespace = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    keys = []
    token = None
    while True:
        query = {"list-type": "2", "max-keys": "1000"}
        if token:
            query["continuation-token"] = token
        root = ElementTree.fromstring(
            _s3_request(
                bucket,
                query,
                access_key=access_key,
                secret_key=secret_key,
            )
        )
        for item in root.findall(f"{namespace}Contents"):
            keys.append(item.findtext(f"{namespace}Key") or "")
            if len(keys) > PURGE_MAX_OBJECTS:
                raise GarageError(
                    413,
                    f"Purge refused above the {PURGE_MAX_OBJECTS:,}-object safety limit.",
                )
        if root.findtext(f"{namespace}IsTruncated") != "true":
            break
        token = root.findtext(f"{namespace}NextContinuationToken")
        if not token:
            break
    return [key for key in keys if key]


def delete_s3_objects(
    bucket: str, keys: list[str], access_key: str, secret_key: str
) -> None:
    """Delete objects in S3's 1,000-key batch format."""
    namespace = "http://s3.amazonaws.com/doc/2006-03-01/"
    for start in range(0, len(keys), 1000):
        root = ElementTree.Element(f"{{{namespace}}}Delete")
        for key in keys[start : start + 1000]:
            item = ElementTree.SubElement(root, f"{{{namespace}}}Object")
            ElementTree.SubElement(item, f"{{{namespace}}}Key").text = key
        body = ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)
        response = ElementTree.fromstring(
            _s3_request(
                bucket,
                {"delete": ""},
                method="POST",
                body=body,
                access_key=access_key,
                secret_key=secret_key,
            )
        )
        errors = response.findall(f"{{{namespace}}}Error")
        if errors:
            detail = errors[0].findtext(f"{{{namespace}}}Message") or "S3 object delete failed."
            raise GarageError(502, detail)


def human_bytes(value) -> str:
    try:
        size = float(value or 0)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return "?"


def _load_archived_buckets() -> list[dict]:
    try:
        with open(ARCHIVE_STORE, encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, list) else []
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as error:
        print(f"could not read archived bucket state: {error}", flush=True)
        return []


def _save_archived_buckets(records: list[dict]) -> None:
    directory = os.path.dirname(ARCHIVE_STORE) or "."
    os.makedirs(directory, exist_ok=True)
    temporary = ARCHIVE_STORE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=1)
    os.replace(temporary, ARCHIVE_STORE)
    os.chmod(ARCHIVE_STORE, 0o600)


def _load_bucket_names() -> dict[str, str]:
    try:
        with open(BUCKET_NAME_STORE, encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            return {}
        return {
            str(bucket_id): str(label).strip()
            for bucket_id, label in value.items()
            if str(bucket_id).strip() and str(label).strip()
        }
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"could not read bucket friendly names: {error}", flush=True)
        return {}


def _save_bucket_names(names: dict[str, str]) -> None:
    directory = os.path.dirname(BUCKET_NAME_STORE) or "."
    os.makedirs(directory, exist_ok=True)
    temporary = BUCKET_NAME_STORE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(names, handle, indent=1, sort_keys=True)
    os.replace(temporary, BUCKET_NAME_STORE)
    os.chmod(BUCKET_NAME_STORE, 0o600)


def bucket_friendly_name(bucket_id: str) -> str | None:
    with BUCKET_NAME_LOCK:
        return _load_bucket_names().get(bucket_id)


def set_bucket_friendly_name(bucket_id: str, label: str) -> str | None:
    """Persist a display label for a real Garage bucket ID; blank clears it."""
    bucket_id = str(bucket_id or "").strip()
    label = str(label or "").strip()
    if not bucket_id:
        raise GarageError(400, "A bucket ID is required.")
    if len(label) > 80:
        raise GarageError(400, "Friendly names must be 80 characters or fewer.")
    matches = [
        bucket
        for bucket in garage("/v2/ListBuckets")
        if bucket.get("id") == bucket_id
    ]
    if not matches:
        raise GarageError(404, "That Garage bucket no longer exists.")
    with BUCKET_NAME_LOCK:
        names = _load_bucket_names()
        if label:
            names[bucket_id] = label
        else:
            names.pop(bucket_id, None)
        _save_bucket_names(names)
    return label or None


def clear_bucket_friendly_name(bucket_id: str) -> None:
    with BUCKET_NAME_LOCK:
        names = _load_bucket_names()
        if bucket_id in names:
            names.pop(bucket_id, None)
            _save_bucket_names(names)


def _archive_time(value: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def archived_bucket_overview() -> list[dict]:
    now = datetime.datetime.now(datetime.timezone.utc)
    with ARCHIVE_LOCK:
        records = _load_archived_buckets()
    out = []
    for record in records:
        try:
            purge_at = _archive_time(record["purgeAt"])
            remaining = max(0, int((purge_at - now).total_seconds()))
        except (KeyError, TypeError, ValueError):
            remaining = 0
        out.append(
            {
                "id": record.get("bucketId", ""),
                "name": record.get("name", ""),
                "friendlyName": bucket_friendly_name(record.get("bucketId", "")),
                "archivedAt": record.get("archivedAt"),
                "purgeAt": record.get("purgeAt"),
                "daysRemaining": (remaining + 86399) // 86400,
                "objects": record.get("objects"),
                "bytes": record.get("bytes"),
                "lastError": record.get("lastError"),
            }
        )
    out.sort(key=lambda item: item.get("purgeAt") or "")
    return out


def archive_bucket(name: str) -> dict:
    """Hide a bucket now and retain its Garage data until the purge date."""
    with ARCHIVE_LOCK:
        records = _load_archived_buckets()
        if any(record.get("name") == name for record in records):
            raise GarageError(409, "That bucket is already archived.")
        matches = [
            bucket
            for bucket in garage("/v2/ListBuckets")
            if name in (bucket.get("globalAliases") or [])
        ]
        if not matches:
            raise GarageError(404, "No bucket has that exact name.")
        if len(matches) > 1:
            raise GarageError(409, "That name matches more than one bucket.")
        bucket = matches[0]
        bucket_id = bucket.get("id", "")
        try:
            info = garage(f"/v2/GetBucketInfo?id={urllib.parse.quote(bucket_id)}")
        except GarageError:
            info = {}
        now = datetime.datetime.now(datetime.timezone.utc)
        record = {
            "bucketId": bucket_id,
            "name": name,
            "archivedAt": now.isoformat(timespec="seconds"),
            "purgeAt": (now + datetime.timedelta(days=ARCHIVE_DAYS)).isoformat(
                timespec="seconds"
            ),
            "objects": info.get("objects"),
            "bytes": info.get("bytes"),
        }
        records.append(record)
        _save_archived_buckets(records)
        return record


def restore_bucket(name: str) -> bool:
    """Remove the soft-delete marker without changing Garage data."""
    with ARCHIVE_LOCK:
        records = _load_archived_buckets()
        remaining = [record for record in records if record.get("name") != name]
        if len(remaining) == len(records):
            raise GarageError(404, "No archived bucket has that exact name.")
        _save_archived_buckets(remaining)
    return True


def _delete_credentials(bucket_info: dict) -> tuple[str, str]:
    if DELETE_ACCESS_KEY and DELETE_SECRET_KEY:
        return DELETE_ACCESS_KEY, DELETE_SECRET_KEY
    candidates = sorted(
        bucket_info.get("keys") or [],
        key=lambda item: (
            not ((item.get("permissions") or {}).get("owner")),
            not ((item.get("permissions") or {}).get("write")),
        ),
    )
    for item in candidates:
        if not any(
            (item.get("permissions") or {}).get(permission)
            for permission in ("owner", "write")
        ):
            continue
        access_key_id = item.get("accessKeyId")
        if not access_key_id:
            continue
        info = garage(
            "/v2/GetKeyInfo?id="
            + urllib.parse.quote(access_key_id)
            + "&showSecretKey=true"
        )
        secret = info.get("secretAccessKey")
        if secret:
            return access_key_id, secret
    raise GarageError(
        403,
        "No owner/write S3 key is available to purge this bucket.",
    )


def _purge_bucket(record: dict) -> None:
    bucket_id = record.get("bucketId", "")
    if not bucket_id:
        raise GarageError(400, "Archived bucket has no Garage id.")
    info = garage(f"/v2/GetBucketInfo?id={urllib.parse.quote(bucket_id)}")
    object_count = info.get("objects")
    # Treat an unknown count as potentially non-empty. The admin endpoint may
    # omit accounting briefly, but DeleteBucket still requires an empty bucket.
    if object_count != 0:
        access_key, secret_key = _delete_credentials(info)
        keys = s3_object_keys(record["name"], access_key, secret_key)
        delete_s3_objects(record["name"], keys, access_key, secret_key)
    try:
        garage(
            "/v2/CleanupIncompleteUploads",
            "POST",
            {"bucketId": bucket_id, "olderThanSecs": 0},
        )
    except GarageError as error:
        print(
            f"could not clean incomplete uploads for {record['name']}: {error.message}",
            flush=True,
        )
    garage(
        "/v2/DeleteBucket?id=" + urllib.parse.quote(bucket_id),
        "POST",
    )


def purge_archived_buckets() -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    with ARCHIVE_LOCK:
        due = []
        records = _load_archived_buckets()
        for record in records:
            try:
                if _archive_time(record.get("purgeAt", "")) <= now:
                    due.append(record)
            except (TypeError, ValueError):
                record["lastError"] = "Invalid purge date in archive state."
                record["lastAttemptAt"] = now.isoformat(timespec="seconds")
                print(
                    f"archived bucket has invalid purge date: {record.get('name')}",
                    flush=True,
                )
        if any(record.get("lastError") for record in records):
            _save_archived_buckets(records)
    for record in due:
        with ARCHIVE_LOCK:
            records = _load_archived_buckets()
            current = next(
                (
                    item
                    for item in records
                    if item.get("bucketId") == record.get("bucketId")
                ),
                None,
            )
            if current is None:
                continue
            try:
                _purge_bucket(current)
            except (GarageError, KeyError, ValueError) as error:
                current["lastError"] = str(error)
                current["lastAttemptAt"] = now.isoformat(timespec="seconds")
                _save_archived_buckets(records)
                print(
                    f"archived bucket purge pending for {current.get('name')}: {error}",
                    flush=True,
                )
                continue
            records = [
                item
                for item in records
                if item.get("bucketId") != current.get("bucketId")
            ]
            _save_archived_buckets(records)
            clear_bucket_friendly_name(current.get("bucketId", ""))
            print(f"purged archived bucket {current.get('name')}", flush=True)


def archive_purge_loop() -> None:
    while True:
        try:
            purge_archived_buckets()
        except Exception as error:
            print(f"archived bucket purge loop failed: {error}", flush=True)
        time.sleep(3600)


def bucket_overview(capacity_bytes: int | None = None) -> list[dict]:
    """Buckets with their sizes; a bucket whose detail lookup fails still shows."""
    out = []
    restic_passwords = _load_restic_passwords() if RESTIC_ENABLED else {}
    restic_checks = _load_restic_checks() if RESTIC_ENABLED else {}
    with ARCHIVE_LOCK:
        archived = _load_archived_buckets()
    archived_ids = {record.get("bucketId") for record in archived}
    archived_names = {record.get("name") for record in archived}
    for bucket in garage("/v2/ListBuckets"):
        aliases = bucket.get("globalAliases") or []
        if bucket.get("id") in archived_ids or archived_names.intersection(aliases):
            continue
        entry = {
            "id": bucket.get("id", ""),
            "aliases": bucket.get("globalAliases") or [],
            "friendlyName": bucket_friendly_name(bucket.get("id", "")),
            "created": (bucket.get("created") or "")[:19].replace("T", " "),
            "objects": None,
            "bytes": None,
            "keys": [],
            "error": None,
            "backup": None,
            "latest": None,
            "latestError": None,
            "restic": None,
            "public": public_paths(
                (bucket.get("globalAliases") or [None])[0] or ""
            ),
        }
        try:
            info = garage(f"/v2/GetBucketInfo?id={urllib.parse.quote(entry['id'])}")
            entry["objects"] = info.get("objects")
            entry["bytes"] = info.get("bytes")
            entry["keys"] = [
                {
                    "id": item.get("accessKeyId", ""),
                    "name": item.get("name", ""),
                    "read": (item.get("permissions") or {}).get("read", False),
                    "write": (item.get("permissions") or {}).get("write", False),
                    "owner": (item.get("permissions") or {}).get("owner", False),
                }
                for item in (info.get("keys") or [])
            ]
        except GarageError as error:
            entry["error"] = error.message
        if (BACKUP_AGE_ENABLED or RESTIC_ENABLED) and entry["objects"] is not None:
            name = entry["aliases"][0] if entry["aliases"] else None
            should_scan = name and (
                RESTIC_ENABLED or not BACKUP_BUCKETS or name in BACKUP_BUCKETS
            )
            if should_scan:
                try:
                    details = bucket_objects(name)
                    if BACKUP_AGE_ENABLED and (
                        not BACKUP_BUCKETS or name in BACKUP_BUCKETS
                    ):
                        entry["backup"] = {
                            key: value
                            for key, value in details.items()
                            if key not in {"latest", "resticStyle"}
                        }
                        entry["latest"] = details["latest"]
                        entry["latestTruncated"] = details["truncated"]
                    if RESTIC_ENABLED:
                        entry["restic"] = _restic_status(
                            name,
                            details.get("resticStyle") or {},
                            restic_passwords,
                            restic_checks,
                        )
                except GarageError as error:
                    detail = _bucket_objects_error(error)
                    entry["backup"] = {"error": detail}
                    entry["latestError"] = detail
                    if RESTIC_ENABLED:
                        entry["restic"] = {
                            "enabled": True,
                            "detected": False,
                            "markers": [],
                            "passwordConfigured": bool(
                                restic_passwords.get(name)
                                or os.path.isfile(RESTIC_PASSWORD_FILE)
                            ),
                            "passwordSource": "saved"
                            if restic_passwords.get(name)
                            else (
                                "default file"
                                if os.path.isfile(RESTIC_PASSWORD_FILE)
                                else None
                            ),
                            "lastCheck": restic_checks.get(name),
                            "error": detail,
                        }
        if capacity_bytes and entry["bytes"] is not None:
            try:
                entry["usagePercent"] = round(
                    max(0, float(entry["bytes"])) / capacity_bytes * 100, 4
                )
            except (TypeError, ValueError):
                entry["usagePercent"] = None
        else:
            entry["usagePercent"] = None
        out.append(entry)
    out.sort(key=lambda item: (item["aliases"][0] if item["aliases"] else item["id"]))
    return out


GARAGE_UPSTREAM_REPO = "deuxfleurs-org/garage"
_version_cache: dict = {"at": 0.0, "data": None}
_VERSION_CACHE_SECONDS = 6 * 3600


def garage_version_status() -> dict:
    """Compare the cluster's Garage version with the newest upstream tag.

    Garage publishes tags rather than GitHub Releases, so the tag list is the
    source of truth. Failures degrade to "unknown" — a flaky upstream check
    must never break the dashboard.
    """
    global _version_cache
    now = time.time()
    if _version_cache["data"] is not None and now - _version_cache["at"] < _VERSION_CACHE_SECONDS:
        return _version_cache["data"]
    result: dict = {"current": None, "latest": None, "updateAvailable": False, "checkedAt": None, "error": None}
    try:
        status = garage("/v2/GetClusterStatus")
        versions = {
            node.get("garageVersion")
            for node in (status.get("nodes") or [])
            if node.get("garageVersion")
        }
        if versions:
            result["current"] = sorted(versions)[-1]
    except GarageError as error:
        result["error"] = f"Cluster version unknown: {error.message}"
    if result["current"]:
        try:
            request = urllib.request.Request(
                f"https://api.github.com/repos/{GARAGE_UPSTREAM_REPO}/tags?per_page=100",
                headers={"Accept": "application/vnd.github+json", "User-Agent": "garage-admin-panel"},
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                tags = json.loads(response.read())
            stable = sorted(
                (tag.get("name", "") for tag in tags),
                key=lambda name: [int(part) for part in name.lstrip("v").split(".") if part.isdigit()],
            )
            stable = [name for name in stable if name.startswith("v") and "-" not in name]
            if stable:
                result["latest"] = stable[-1]
                def _key(version):
                    return [int(part) for part in version.lstrip("v").split(".")]
                result["updateAvailable"] = _key(result["latest"]) > _key(result["current"])
                result["checkedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as error:
            result["error"] = f"Upstream check failed: {error}"
    _version_cache = {"at": now, "data": result}
    return result


def cluster_overview() -> dict:
    try:
        status = garage("/v2/GetClusterStatus")
    except GarageError as error:
        return {"error": error.message}
    nodes = status.get("nodes") or []
    capacities = [
        _as_int((node.get("role") or {}).get("capacity"))
        or _as_int((node.get("dataPartition") or {}).get("total"))
        for node in nodes
    ]
    return {
        "layoutVersion": status.get("layoutVersion"),
        "capacityBytes": sum(capacities),
        "nodes": [
            {
                "hostname": node.get("hostname"),
                "id": (node.get("id") or "")[:16],
                "capacity": human_bytes((node.get("role") or {}).get("capacity")),
                "available": human_bytes(
                    (node.get("dataPartition") or {}).get("available")
                ),
                "total": human_bytes((node.get("dataPartition") or {}).get("total")),
            }
            for node in nodes
        ],
    }


def _as_int(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _load_api_keys() -> list[dict]:
    try:
        with open(API_KEY_STORE, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return []


def _save_api_keys(keys: list[dict]) -> None:
    os.makedirs(os.path.dirname(API_KEY_STORE), exist_ok=True)
    temporary = API_KEY_STORE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(keys, handle, indent=1)
    os.replace(temporary, API_KEY_STORE)
    os.chmod(API_KEY_STORE, 0o600)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


KEY_SECRET_KDF_ROUNDS = 200_000
KEY_SECRET_VERSION = "v1"


def _key_secret_key(salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        PANEL_PASSWORD.encode(),
        salt,
        KEY_SECRET_KDF_ROUNDS,
        dklen=32,
    )


def _key_secret_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        stream.extend(
            hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        )
        counter += 1
    return bytes(stream[:length])


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _encrypt_key_secrets(values: dict[str, str]) -> dict:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    key = _key_secret_key(salt)
    plaintext = json.dumps(values, sort_keys=True).encode()
    ciphertext = _xor_bytes(plaintext, _key_secret_stream(key, nonce, len(plaintext)))
    authenticated = KEY_SECRET_VERSION.encode() + salt + nonce + ciphertext
    tag = hmac.new(key, authenticated, hashlib.sha256).digest()
    return {
        "version": KEY_SECRET_VERSION,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def _decrypt_key_secrets(envelope: dict) -> dict[str, str]:
    if envelope.get("version") != KEY_SECRET_VERSION:
        raise ValueError("unsupported key secret store version")
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    tag = base64.b64decode(envelope["tag"])
    key = _key_secret_key(salt)
    authenticated = KEY_SECRET_VERSION.encode() + salt + nonce + ciphertext
    expected = hmac.new(key, authenticated, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("key secret store authentication failed")
    plaintext = _xor_bytes(
        ciphertext, _key_secret_stream(key, nonce, len(ciphertext))
    )
    values = json.loads(plaintext)
    if not isinstance(values, dict):
        raise ValueError("key secret store is not a mapping")
    return {str(key): str(value) for key, value in values.items()}


def _load_key_secrets() -> dict[str, str]:
    try:
        with open(KEY_SECRET_STORE, encoding="utf-8") as handle:
            return _decrypt_key_secrets(json.load(handle))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"could not read encrypted S3 key secrets: {error}", flush=True)
        return {}


def _save_key_secrets(values: dict[str, str]) -> None:
    directory = os.path.dirname(KEY_SECRET_STORE) or "."
    os.makedirs(directory, exist_ok=True)
    temporary = KEY_SECRET_STORE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(_encrypt_key_secrets(values), handle, indent=1)
    os.replace(temporary, KEY_SECRET_STORE)
    os.chmod(KEY_SECRET_STORE, 0o600)


def _load_restic_passwords() -> dict[str, str]:
    try:
        with open(RESTIC_PASSWORD_STORE, encoding="utf-8") as handle:
            return _decrypt_key_secrets(json.load(handle))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"could not read encrypted Restic passwords: {error}", flush=True)
        return {}


def _save_restic_passwords(values: dict[str, str]) -> None:
    directory = os.path.dirname(RESTIC_PASSWORD_STORE) or "."
    os.makedirs(directory, exist_ok=True)
    temporary = RESTIC_PASSWORD_STORE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(_encrypt_key_secrets(values), handle, indent=1)
    os.replace(temporary, RESTIC_PASSWORD_STORE)
    os.chmod(RESTIC_PASSWORD_STORE, 0o600)


def _load_restic_checks() -> dict[str, dict]:
    try:
        with open(RESTIC_CHECK_STORE, encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"could not read Restic check state: {error}", flush=True)
        return {}


def _save_restic_checks(values: dict[str, dict]) -> None:
    directory = os.path.dirname(RESTIC_CHECK_STORE) or "."
    os.makedirs(directory, exist_ok=True)
    temporary = RESTIC_CHECK_STORE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(values, handle, indent=1)
    os.replace(temporary, RESTIC_CHECK_STORE)
    os.chmod(RESTIC_CHECK_STORE, 0o600)


def _restic_status(
    name: str,
    style: dict,
    passwords: dict[str, str],
    checks: dict[str, dict],
) -> dict | None:
    if not RESTIC_ENABLED:
        return None
    password_source = "saved" if passwords.get(name) else None
    if password_source is None and os.path.isfile(RESTIC_PASSWORD_FILE):
        password_source = "default file"
    return {
        "enabled": True,
        "detected": bool(style.get("detected")),
        "markers": style.get("markers") or [],
        "passwordConfigured": password_source is not None,
        "passwordSource": password_source,
        "lastCheck": checks.get(name),
    }


def _command_result(args: list[str], timeout: int) -> dict:
    try:
        completed = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (completed.stdout + completed.stderr).strip()
        return {
            "returncode": completed.returncode,
            "output": output[-4000:],
        }
    except FileNotFoundError:
        return {"returncode": 127, "output": f"Command not found: {args[0]}"}
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "output": "Command timed out."}
    except OSError as error:
        return {"returncode": 126, "output": str(error)}


def _systemd_fields(unit: str) -> tuple[dict[str, str], str | None]:
    result = _command_result(
        [
            SYSTEMCTL,
            "show",
            unit,
            "--no-pager",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "MainPID",
            "-p",
            "ExecMainStatus",
            "-p",
            "ExecMainStartTimestamp",
        ],
        20,
    )
    if result["returncode"] != 0:
        return {}, result["output"] or "systemd status failed."
    fields = {}
    for line in result["output"].splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    return fields, None


def cloudflared_status() -> dict:
    if not CLOUDFLARED_ENABLED:
        return {"enabled": False}
    version = _command_result([CLOUDFLARED_BIN, "version"], 20)
    fields, systemd_error = _systemd_fields(CLOUDFLARED_SERVICE)
    return {
        "enabled": True,
        "service": CLOUDFLARED_SERVICE,
        "active": fields.get("ActiveState") == "active",
        "activeState": fields.get("ActiveState"),
        "subState": fields.get("SubState"),
        "mainPid": fields.get("MainPID"),
        "execMainStatus": fields.get("ExecMainStatus"),
        "started": fields.get("ExecMainStartTimestamp"),
        "version": (version["output"].splitlines() or ["unknown"])[0],
        "error": systemd_error
        or (version["output"] if version["returncode"] != 0 else None),
    }


def update_cloudflared() -> dict:
    if not CLOUDFLARED_ENABLED:
        raise GarageError(404, "Cloudflared integration is disabled.")
    with CLOUDFLARED_LOCK:
        result = _command_result(
            [SYSTEMCTL, "start", CLOUDFLARED_UPDATE_SERVICE],
            CLOUDFLARED_TIMEOUT,
        )
    if result["returncode"] != 0:
        raise GarageError(
            502,
            "Cloudflared update failed: "
            + (result["output"] or "the update service returned an error."),
        )
    return {"ok": True, "output": result["output"], "status": cloudflared_status()}


def save_restic_password(bucket: str, password: str) -> None:
    if not RESTIC_ENABLED:
        raise GarageError(404, "Restic checks are disabled.")
    values = _load_restic_passwords()
    values[bucket] = password
    try:
        _save_restic_passwords(values)
    except OSError as error:
        raise GarageError(500, f"Could not store the Restic password: {error}") from error


def run_restic_check(bucket: str) -> dict:
    if not RESTIC_ENABLED:
        raise GarageError(404, "Restic checks are disabled.")
    details = bucket_objects(bucket)
    style = details.get("resticStyle") or {}
    if not style.get("detected"):
        raise GarageError(400, "That bucket does not look like a Restic repository.")
    if not os.path.isfile(RESTIC_BIN):
        raise GarageError(503, f"Restic is not available at {RESTIC_BIN}.")
    if not S3_ACCESS_KEY or not S3_SECRET_KEY:
        raise GarageError(
            503,
            "Restic checks need the configured S3 access and secret keys.",
        )
    passwords = _load_restic_passwords()
    password = passwords.get(bucket)
    password_source = "saved"
    environment = os.environ.copy()
    # Restic's S3 backend reads AWS-compatible credentials from the process
    # environment. The panel already uses these credentials for its bounded
    # listing, but passing only RESTIC_PASSWORD made the health check fail with
    # "no credentials found".
    environment["AWS_ACCESS_KEY_ID"] = S3_ACCESS_KEY
    environment["AWS_SECRET_ACCESS_KEY"] = S3_SECRET_KEY
    environment["AWS_DEFAULT_REGION"] = S3_REGION
    if password:
        environment["RESTIC_PASSWORD"] = password
        environment.pop("RESTIC_PASSWORD_FILE", None)
    elif os.path.isfile(RESTIC_PASSWORD_FILE):
        environment["RESTIC_PASSWORD_FILE"] = RESTIC_PASSWORD_FILE
        password_source = "default file"
    else:
        raise GarageError(400, "Enter and save the password for this Restic repository first.")
    repository = f"s3:{S3_ENDPOINT}/{bucket}"
    started = time.monotonic()
    with RESTIC_LOCK:
        try:
            completed = subprocess.run(
                [
                    RESTIC_BIN,
                    "check",
                    "--no-lock",
                    "--no-cache",
                    "--repo",
                    repository,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=RESTIC_CHECK_TIMEOUT,
                check=False,
                cwd="/tmp",
                env=environment,
            )
            output = (completed.stdout + completed.stderr).strip()
            record = {
                "checkedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(
                    timespec="seconds"
                ),
                "ok": completed.returncode == 0,
                "returncode": completed.returncode,
                "passwordSource": password_source,
                "durationSeconds": round(time.monotonic() - started, 1),
                "summary": output[-3000:] or "Restic returned no output.",
            }
        except subprocess.TimeoutExpired:
            record = {
                "checkedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(
                    timespec="seconds"
                ),
                "ok": False,
                "returncode": 124,
                "passwordSource": password_source,
                "durationSeconds": round(time.monotonic() - started, 1),
                "summary": "Restic health check timed out.",
            }
    checks = _load_restic_checks()
    checks[bucket] = record
    try:
        _save_restic_checks(checks)
    except OSError as error:
        print(f"could not persist Restic check state: {error}", flush=True)
    return record


def remember_key_secret(key: dict) -> None:
    access_key_id = key.get("accessKeyId") or key.get("id")
    secret = key.get("secretAccessKey")
    if not access_key_id or not secret:
        return
    values = _load_key_secrets()
    values[str(access_key_id)] = str(secret)
    try:
        _save_key_secrets(values)
    except OSError as error:
        # The key was already created in Garage and its secret is still
        # returned once to the operator, so do not turn a storage failure into
        # a misleading create error.
        print(f"could not persist S3 key secret: {error}", flush=True)


def forget_key_secret(access_key_id: str) -> None:
    values = _load_key_secrets()
    if access_key_id not in values:
        return
    values.pop(access_key_id, None)
    try:
        _save_key_secrets(values)
    except OSError as error:
        print(f"could not remove deleted S3 key secret: {error}", flush=True)


def key_details() -> list[dict]:
    """Return key metadata plus secrets saved by this panel.

    Garage exposes an existing secret only when explicitly asked for it. The
    encrypted local store remains a fallback for older Garage builds that do
    not support that admin API option.
    """
    saved = _load_key_secrets()
    details = []
    for key in garage("/v2/ListKeys"):
        access_key_id = key.get("id") or key.get("accessKeyId") or ""
        info = key
        try:
            info = garage(
                "/v2/GetKeyInfo?id="
                + urllib.parse.quote(str(access_key_id))
                + "&showSecretKey=true"
            )
        except GarageError as error:
            print(
                f"could not retrieve secret for key {access_key_id}: {error.message}",
                flush=True,
            )
        secret = info.get("secretAccessKey") or saved.get(str(access_key_id))
        details.append(
            {
                "id": access_key_id,
                "name": info.get("name") or key.get("name"),
                "created": (info.get("created") or key.get("created") or "")[:19].replace("T", " "),
                "expired": info.get("expired", key.get("expired")),
                "secretAccessKey": secret,
                "secretAvailable": bool(secret),
            }
        )
    return details


def access_key_accounts() -> list[dict]:
    """Return safe key metadata for the grant selector; never return secrets."""
    accounts = []
    for key in garage("/v2/ListKeys"):
        access_key_id = key.get("id") or key.get("accessKeyId") or ""
        if not access_key_id:
            continue
        accounts.append(
            {
                "id": access_key_id,
                "name": key.get("name") or "(unnamed)",
                "expired": bool(key.get("expired")),
            }
        )
    return accounts


def create_api_key(name: str) -> dict:
    """Returns the token exactly once; only its hash is persisted."""
    token = "gp_" + secrets.token_urlsafe(32)
    entry = {
        "id": secrets.token_hex(6),
        "name": name[:64],
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "hash": _hash_token(token),
        "last_used": None,
        "last_used_from": None,
    }
    keys = _load_api_keys()
    keys.append(entry)
    _save_api_keys(keys)
    public = {k: v for k, v in entry.items() if k != "hash"}
    public["token"] = token
    return public


def api_key_for_token(token: str, address: str) -> dict | None:
    """Match a presented token and stamp its last use."""
    if not token:
        return None
    digest = _hash_token(token)
    keys = _load_api_keys()
    for entry in keys:
        if hmac.compare_digest(entry.get("hash", ""), digest):
            entry["last_used"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(timespec="seconds")
            entry["last_used_from"] = address
            try:
                _save_api_keys(keys)
            except OSError as error:
                print(f"could not record API key use: {error}", flush=True)
            return entry
    return None


def record_signin(user: str, address: str, outcome: str) -> None:
    """Append-only sign-in trail. Never fatal: an unwritable log must not stop
    someone getting into the panel."""
    line = (
        datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        + f"\t{outcome}\t{user[:64]}\t{address}\n"
    )
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError as error:
        print(f"audit log unavailable: {error}", flush=True)


def recent_signins(limit: int = 15) -> list[dict]:
    try:
        with open(AUDIT_LOG, encoding="utf-8") as handle:
            rows = handle.read().splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for row in reversed(rows):
        parts = row.split("\t")
        if len(parts) == 4:
            out.append(
                {"at": parts[0], "outcome": parts[1], "user": parts[2], "from": parts[3]}
            )
    return out


def record_activity(
    action: str,
    target: str = "",
    outcome: str = "ok",
    detail: str = "",
    address: str = "",
) -> None:
    """Append a non-secret operator activity entry without blocking the UI."""
    entry = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "action": str(action)[:64],
        "target": str(target)[:160],
        "outcome": str(outcome)[:32],
        "detail": str(detail)[:300],
        "from": str(address)[:128],
    }
    try:
        os.makedirs(os.path.dirname(ACTIVITY_LOG), exist_ok=True)
        with open(ACTIVITY_LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError as error:
        print(f"activity log unavailable: {error}", flush=True)


def recent_activity(limit: int = 30) -> list[dict]:
    try:
        with open(ACTIVITY_LOG, encoding="utf-8") as handle:
            rows = handle.read().splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for row in reversed(rows):
        try:
            entry = json.loads(row)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(entry, dict) and entry.get("at") and entry.get("action"):
            out.append(entry)
    return out


def public_paths(name: str) -> dict:
    """Where this bucket can be reached from outside the container."""
    if not name:
        return {}
    paths = {}
    if S3_PUBLIC_ENDPOINT:
        paths["path_style"] = f"{S3_PUBLIC_ENDPOINT}/{name}"
        paths["s3_endpoint"] = S3_PUBLIC_ENDPOINT
    return paths


def connection_settings() -> dict:
    public_endpoint = S3_PUBLIC_ENDPOINT or None
    return {
        "s3Endpoint": public_endpoint or S3_ENDPOINT,
        "internalS3Endpoint": S3_ENDPOINT,
        "region": S3_REGION,
        "accessKeyId": S3_ACCESS_KEY,
        "credentialsConfigured": bool(S3_ACCESS_KEY and S3_SECRET_KEY),
        "secretKeyHidden": bool(S3_SECRET_KEY),
        "browserConfigured": bool(
            (S3_ACCESS_KEY and S3_SECRET_KEY)
            or (S3_BROWSER_ACCESS_KEY and S3_BROWSER_SECRET_KEY)
        ),
        "browserWriteEnabled": bool(
            S3_BROWSER_ACCESS_KEY and S3_BROWSER_SECRET_KEY
        ),
        "browserMaxUploadBytes": S3_BROWSER_UPLOAD_MAX_BYTES,
        "pathStyleTemplate": (
            f"{public_endpoint}/<bucket>" if public_endpoint else None
        ),
        "deleteCredentialsConfigured": bool(
            DELETE_ACCESS_KEY and DELETE_SECRET_KEY
        ),
    }


def active_bucket_named(name: str) -> bool:
    with ARCHIVE_LOCK:
        archived = _load_archived_buckets()
    if any(record.get("name") == name for record in archived):
        return False
    return any(
        name in (bucket.get("globalAliases") or [])
        for bucket in garage("/v2/ListBuckets")
    )


def grant_panel_read_access(bucket_id: str) -> dict:
    """Grant the configured panel S3 key read-only access to one bucket."""
    if not PANEL_AUTO_GRANT_READ:
        return {"enabled": False, "granted": False}
    if not S3_ACCESS_KEY:
        return {
            "enabled": True,
            "granted": False,
            "warning": "S3_ACCESS_KEY is not configured; panel read access was not granted.",
        }
    garage(
        "/v2/AllowBucketKey",
        "POST",
        {
            "bucketId": bucket_id,
            "accessKeyId": S3_ACCESS_KEY,
            "permissions": {"read": True, "write": False, "owner": False},
        },
    )
    return {"enabled": True, "granted": True}


def grant_panel_browser_access(bucket_id: str) -> dict:
    """Grant the optional browser key read/write access on a new bucket."""
    if not S3_BROWSER_ACCESS_KEY:
        return {"enabled": False, "granted": False}
    if not S3_BROWSER_SECRET_KEY:
        return {
            "enabled": True,
            "granted": False,
            "warning": "S3_BROWSER_SECRET_KEY is not configured; browser write access was not granted.",
        }
    garage(
        "/v2/AllowBucketKey",
        "POST",
        {
            "bucketId": bucket_id,
            "accessKeyId": S3_BROWSER_ACCESS_KEY,
            "permissions": {"read": True, "write": True, "owner": False},
        },
    )
    return {"enabled": True, "granted": True}


class Handler(BaseHTTPRequestHandler):
    server_version = "GaragePanel/2.0.0"

    def log_message(self, fmt: str, *args) -> None:  # keep the journal readable
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)

    # ---- auth -------------------------------------------------------------
    def issue_session(self, remember: bool = False) -> str:
        """A cookie value of expiry.signature — no password, no server state."""
        hours = SESSION_HOURS
        if remember and REMEMBER_ME_DAYS:
            hours = max(hours, REMEMBER_ME_DAYS * 24)
        expires = int(time.time()) + hours * 3600
        payload = f"{PANEL_USER}:{expires}"
        signature = hmac.new(
            SESSION_SECRET.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        return f"{expires}.{signature}"

    def session_valid(self) -> bool:
        cookies = self.headers.get("Cookie", "")
        value = ""
        for part in cookies.split(";"):
            name, _, candidate = part.strip().partition("=")
            if name == COOKIE_NAME:
                value = candidate
                break
        if not value or "." not in value:
            return False
        expires_text, _, signature = value.partition(".")
        try:
            expires = int(expires_text)
        except ValueError:
            return False
        if expires < time.time():
            return False
        expected = hmac.new(
            SESSION_SECRET.encode(),
            f"{PANEL_USER}:{expires}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(signature, expected)

    def credentials_valid(self, user: str, password: str) -> bool:
        if not PANEL_PASSWORD:
            # Fail closed: an unset password must not mean "no auth".
            return False
        return hmac.compare_digest(user, PANEL_USER) and hmac.compare_digest(
            password, PANEL_PASSWORD
        )

    def send_login_page(self, message: str = "", status: int = 200) -> None:
        body = (
            LOGIN_PAGE
            .replace("{{message}}", message)
            .replace("${REMEMBER_DAYS}", f"{REMEMBER_ME_DAYS} days" if REMEMBER_ME_DAYS else "this device only")
            .encode()
        )
        if not REMEMBER_ME_DAYS:
            body = body.replace(b'name="remember"', b'name="remember" disabled')
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def bearer_key(self) -> dict | None:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        return api_key_for_token(header[7:].strip(), self.address_string())

    def require_auth(self) -> bool:
        if self.session_valid():
            return True
        # Scripts authenticate with an API key instead of a browser session.
        if self.bearer_key() is not None:
            return True
        # HTML callers get the form; API callers get JSON they can act on.
        if self.path.startswith("/api/"):
            self.reply_json({"error": "Session expired. Reload and sign in."}, 401)
        else:
            self.send_login_page("", 401)
        return False

    # ---- plumbing ---------------------------------------------------------
    def reply_json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}

    # ---- routes -----------------------------------------------------------
    @staticmethod
    def _safe(fn, *args, **kwargs):
        """Run an overview helper; a partial Garage failure degrades that
        section instead of blanking the whole dashboard."""
        try:
            return fn(*args, **kwargs)
        except GarageError as error:
            return {"error": error.message}

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/login":
            return self.send_login_page()
        if path == "/logout":
            self.send_response(303)
            self.send_header("Location", "/login")
            self.send_header(
                "Set-Cookie",
                f"{COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict",
            )
            self.end_headers()
            return
        if not self.require_auth():
            return
        if path in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'",
            )
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/bucket/objects":
            values = urllib.parse.parse_qs(parsed.query)
            bucket = (values.get("bucket") or [""])[0]
            prefix = (values.get("prefix") or [""])[0]
            continuation = (values.get("continuation") or [""])[0]
            try:
                self.reply_json(browser_list_objects(bucket, prefix, continuation))
            except GarageError as error:
                self.reply_json({"error": _bucket_objects_error(error)}, error.status)
            return
        if path == "/api/bucket/download":
            values = urllib.parse.parse_qs(parsed.query)
            bucket = (values.get("bucket") or [""])[0]
            key = (values.get("key") or [""])[0]
            try:
                bucket = require_active_bucket(bucket)
                key = _checked_object_key(key)
                access_key, secret_key = browser_read_credentials()
                body = _s3_request(
                    bucket,
                    {},
                    access_key=access_key,
                    secret_key=secret_key,
                    object_key=key,
                )
            except GarageError as error:
                self.reply_json({"error": _bucket_objects_error(error)}, error.status)
                return
            filename = key.rsplit("/", 1)[-1] or "download"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Content-Disposition",
                "attachment; filename*=UTF-8''"
                + urllib.parse.quote(filename, safe=""),
            )
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            record_activity(
                "object.download",
                f"{bucket} / {key}",
                detail=f"{len(body)} bytes",
                address=self.address_string(),
            )
            return
        if path == "/api/overview":
            try:
                cluster = cluster_overview()
                self.reply_json(
                    {
                        "cluster": cluster,
                        "garageVersion": garage_version_status(),
                        "buckets": self._safe(bucket_overview, cluster.get("capacityBytes")),
                        "archivedBuckets": self._safe(archived_bucket_overview),
                        "archiveDays": ARCHIVE_DAYS,
                        "connectionSettings": self._safe(connection_settings),
                        "cloudflared": self._safe(cloudflared_status),
                        "resticEnabled": RESTIC_ENABLED,
                        "backupAges": BACKUP_AGE_ENABLED,
                        "backupBuckets": BACKUP_BUCKETS,
                        "signins": self._safe(recent_signins),
                        "activity": self._safe(recent_activity),
                        "accessKeys": self._safe(access_key_accounts),
                        "endpoint": {
                            "public": S3_PUBLIC_ENDPOINT,
                        },
                    }
                )
            except GarageError as error:
                self.reply_json({"error": error.message}, error.status)
            return
        if path == "/api/apikeys":
            return self.reply_json(
                {
                    "keys": [
                        {k: v for k, v in entry.items() if k != "hash"}
                        for entry in _load_api_keys()
                    ]
                }
            )
        if path == "/openapi.json":
            return self.reply_json(openapi_spec())
        if path == "/docs":
            body = DOCS_PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
                "img-src 'self' data:; base-uri 'none'",
            )
            self.end_headers()
            return self.wfile.write(body)
        if path.startswith("/static/"):
            name = os.path.basename(path)
            if name not in {"swagger-ui.css", "swagger-ui-bundle.js"}:
                return self.reply_json({"error": "Not found"}, 404)
            try:
                with open(os.path.join(STATIC_DIR, name), "rb") as handle:
                    body = handle.read()
            except OSError:
                return self.reply_json({"error": "Asset missing"}, 404)
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/css" if name.endswith(".css") else "application/javascript",
            )
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "max-age=86400")
            self.end_headers()
            return self.wfile.write(body)
        if path == "/api/keys":
            # Metadata is safe to show; secrets stay masked until the
            # deliberate password re-entry via /api/keys/reveal.
            keys = self._safe(key_details)
            if isinstance(keys, dict):
                return self.reply_json(keys)
            return self.reply_json(
                {
                    "locked": False,
                    "keys": [
                        {**key, "secretAccessKey": None} for key in keys
                    ],
                }
            )
        self.reply_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/login":
            length = int(self.headers.get("Content-Length") or 0)
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            user = (form.get("user") or [""])[0]
            password = (form.get("password") or [""])[0]
            if not self.credentials_valid(user, password):
                record_signin(user or "(blank)", self.address_string(), "FAILED")
                # Same message either way: do not reveal which field was wrong.
                return self.send_login_page("Incorrect username or password.", 401)
            record_signin(user, self.address_string(), "ok")
            remember = bool((form.get("remember") or [""])[0])
            max_age = SESSION_HOURS * 3600
            if remember and REMEMBER_ME_DAYS:
                max_age = max(max_age, REMEMBER_ME_DAYS * 24 * 3600)
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header(
                "Set-Cookie",
                f"{COOKIE_NAME}={self.issue_session(remember)}; Path=/; HttpOnly; "
                f"SameSite=Strict; Max-Age={max_age}",
            )
            self.end_headers()
            return
        if not self.require_auth():
            return
        payload = self.read_json()
        try:
            if path == "/api/buckets/name":
                bucket_id = str(payload.get("bucketId", "")).strip()
                friendly_name = str(payload.get("friendlyName", ""))
                saved_name = set_bucket_friendly_name(bucket_id, friendly_name)
                record_activity(
                    "bucket.name",
                    bucket_id,
                    detail=saved_name or "cleared",
                    address=self.address_string(),
                )
                return self.reply_json(
                    {"ok": True, "bucketId": bucket_id, "friendlyName": saved_name}
                )
            if path == "/api/bucket/upload":
                bucket = str(payload.get("bucket", "")).strip()
                key = str(payload.get("key", ""))
                encoded = payload.get("content")
                if not isinstance(encoded, str) or not encoded:
                    return self.reply_json({"error": "A file is required."}, 400)
                if len(encoded) > ((S3_BROWSER_UPLOAD_MAX_BYTES * 4) // 3) + 4096:
                    return self.reply_json({"error": "Upload is too large."}, 413)
                try:
                    body = base64.b64decode(encoded, validate=True)
                except (ValueError, TypeError):
                    return self.reply_json({"error": "The uploaded file data is invalid."}, 400)
                browser_upload(bucket, key, body, str(payload.get("contentType", "")))
                record_activity(
                    "object.upload",
                    f"{bucket} / {key}",
                    detail=f"{len(body)} bytes",
                    address=self.address_string(),
                )
                return self.reply_json({"ok": True, "bucket": bucket, "key": key, "bytes": len(body)})
            if path == "/api/bucket/delete":
                bucket = str(payload.get("bucket", "")).strip()
                key = _checked_object_key(str(payload.get("key", "")))
                if str(payload.get("confirmation", "")) != key:
                    return self.reply_json({"error": "Confirm the exact object key before deleting."}, 400)
                browser_delete(bucket, key)
                record_activity("object.delete", f"{bucket} / {key}", address=self.address_string())
                return self.reply_json({"ok": True, "bucket": bucket, "key": key})
            if path == "/api/bucket/rename":
                bucket = str(payload.get("bucket", "")).strip()
                key = _checked_object_key(str(payload.get("key", "")))
                new_key = _checked_object_key(str(payload.get("newKey", "")), "The new object key")
                if str(payload.get("confirmation", "")) != key:
                    return self.reply_json({"error": "Confirm the exact current object key before renaming."}, 400)
                browser_rename(bucket, key, new_key)
                record_activity("object.rename", f"{bucket} / {key} -> {new_key}", address=self.address_string())
                return self.reply_json({"ok": True, "bucket": bucket, "key": key, "newKey": new_key})
            if path == "/api/cloudflared/update":
                if str(payload.get("confirmation", "")) != "update cloudflared":
                    return self.reply_json(
                        {"error": "Confirm the Cloudflared update before running it."},
                        400,
                    )
                result = update_cloudflared()
                record_activity("cloudflared.update", outcome="ok", address=self.address_string())
                return self.reply_json(result)
            if path == "/api/restic/password":
                name = str(payload.get("bucket", "")).strip()
                password = str(payload.get("password", ""))
                if not name or not password:
                    return self.reply_json(
                        {"error": "A bucket and Restic password are required."}, 400
                    )
                if not RESTIC_ENABLED:
                    return self.reply_json({"error": "Restic checks are disabled."}, 404)
                if not active_bucket_named(name):
                    return self.reply_json({"error": "No active bucket has that exact name."}, 404)
                save_restic_password(name, password)
                record_activity("restic.password", name, address=self.address_string())
                return self.reply_json({"ok": True, "bucket": name})
            if path == "/api/restic/check":
                name = str(payload.get("bucket", "")).strip()
                if not name:
                    return self.reply_json({"error": "A bucket is required."}, 400)
                if not active_bucket_named(name):
                    return self.reply_json({"error": "No active bucket has that exact name."}, 404)
                result = run_restic_check(name)
                record_activity(
                    "restic.check",
                    name,
                    "ok" if result["ok"] else "failed",
                    result.get("summary", ""),
                    self.address_string(),
                )
                return self.reply_json({"ok": result["ok"], "result": result})
            if path == "/api/buckets/archive":
                name = str(payload.get("name", "")).strip()
                confirmation = str(payload.get("confirmation", "")).strip()
                if not name:
                    return self.reply_json({"error": "A bucket name is required."}, 400)
                if confirmation != name:
                    return self.reply_json(
                        {"error": "Type the exact bucket name to confirm archiving."},
                        400,
                    )
                record = archive_bucket(name)
                record_activity("bucket.archive", name, address=self.address_string())
                return self.reply_json({"ok": True, "bucket": record})
            if path == "/api/buckets/restore":
                name = str(payload.get("name", "")).strip()
                confirmation = str(payload.get("confirmation", "")).strip()
                if not name:
                    return self.reply_json({"error": "A bucket name is required."}, 400)
                if confirmation != name:
                    return self.reply_json(
                        {"error": "Type the exact bucket name to confirm restoring."},
                        400,
                    )
                restore_bucket(name)
                record_activity("bucket.restore", name, address=self.address_string())
                return self.reply_json({"ok": True})
            if path == "/api/buckets":
                name = str(payload.get("name", "")).strip()
                if not name:
                    return self.reply_json({"error": "A bucket name is required."}, 400)
                created = garage("/v2/CreateBucket", "POST", {"globalAlias": name})
                bucket_id = created.get("id") if isinstance(created, dict) else None
                if not bucket_id:
                    bucket_id = next(
                        (
                            item.get("id")
                            for item in garage("/v2/ListBuckets")
                            if name in (item.get("globalAliases") or [])
                        ),
                        None,
                    )
                read_access = (
                    grant_panel_read_access(bucket_id)
                    if bucket_id
                    else {
                        "enabled": PANEL_AUTO_GRANT_READ,
                        "granted": False,
                        "warning": "Garage did not return the new bucket ID; panel read access was not granted.",
                    }
                )
                browser_access = (
                    grant_panel_browser_access(bucket_id)
                    if bucket_id
                    else {
                        "enabled": bool(S3_BROWSER_ACCESS_KEY),
                        "granted": False,
                        "warning": "Garage did not return the new bucket ID; browser write access was not granted.",
                    }
                )
                record_activity(
                    "bucket.create",
                    name,
                    "ok"
                    if read_access.get("granted", True)
                    and browser_access.get("granted", True)
                    else "warning",
                    "; ".join(
                        detail
                        for detail in (
                            "panel read access granted"
                            if read_access.get("granted")
                            else read_access.get("warning", ""),
                            "browser write access granted"
                            if browser_access.get("granted")
                            else browser_access.get("warning", ""),
                        )
                        if detail
                    ),
                    self.address_string(),
                )
                return self.reply_json(
                    {
                        "ok": True,
                        "bucket": created,
                        "panelReadAccess": read_access,
                        "browserAccess": browser_access,
                    }
                )
            if path == "/api/keys":
                name = str(payload.get("name", "")).strip()
                if not name:
                    return self.reply_json({"error": "A key name is required."}, 400)
                # The secret is returned exactly once, by Garage, at creation.
                created = garage("/v2/CreateKey", "POST", {"name": name})
                remember_key_secret(created)
                record_activity("key.create", created.get("accessKeyId") or created.get("id") or name, address=self.address_string())
                return self.reply_json({"ok": True, "key": created})
            if path == "/api/keys/reveal":
                password = str(payload.get("password", ""))
                if not PANEL_PASSWORD or not hmac.compare_digest(
                    password, PANEL_PASSWORD
                ):
                    record_signin(PANEL_USER, self.address_string(), "REAUTH_FAILED")
                    return self.reply_json({"error": "Incorrect password."}, 403)
                record_signin(PANEL_USER, self.address_string(), "REAUTH_OK")
                return self.reply_json({"keys": key_details()})
            if path == "/api/keys/delete":
                access_key_id = str(payload.get("id", "")).strip()
                confirmation = str(payload.get("confirmation", "")).strip()
                if not access_key_id:
                    return self.reply_json({"error": "An access key ID is required."}, 400)
                if confirmation != access_key_id:
                    return self.reply_json(
                        {"error": "Type the exact access key ID to confirm deletion."},
                        400,
                    )
                if not any(
                    (key.get("id") or key.get("accessKeyId")) == access_key_id
                    for key in garage("/v2/ListKeys")
                ):
                    return self.reply_json({"error": "No such Garage access key."}, 404)
                garage(
                    "/v2/DeleteKey?id=" + urllib.parse.quote(access_key_id),
                    "POST",
                )
                forget_key_secret(access_key_id)
                record_activity("key.delete", access_key_id, address=self.address_string())
                return self.reply_json({"ok": True, "id": access_key_id})
            if path == "/api/apikeys":
                name = str(payload.get("name", "")).strip()
                if not name:
                    return self.reply_json({"error": "A key name is required."}, 400)
                created = create_api_key(name)
                record_activity("apikey.create", created.get("id") or name, address=self.address_string())
                return self.reply_json({"ok": True, "key": created})
            if path == "/api/apikeys/revoke":
                key_id = str(payload.get("id", "")).strip()
                keys = _load_api_keys()
                remaining = [entry for entry in keys if entry.get("id") != key_id]
                if len(remaining) == len(keys):
                    return self.reply_json({"error": "No such API key."}, 404)
                _save_api_keys(remaining)
                record_activity("apikey.revoke", key_id, address=self.address_string())
                return self.reply_json({"ok": True})
            if path == "/api/grant":
                bucket = str(payload.get("bucketId", "")).strip()
                key = str(payload.get("accessKeyId", "")).strip()
                if not bucket or not key:
                    return self.reply_json(
                        {"error": "Both a bucket and a key are required."}, 400
                    )
                permissions = {
                    "read": bool(payload.get("read")),
                    "write": bool(payload.get("write")),
                    "owner": bool(payload.get("owner")),
                }
                endpoint = (
                    "/v2/AllowBucketKey" if payload.get("allow", True)
                    else "/v2/DenyBucketKey"
                )
                result = garage(
                    endpoint,
                    "POST",
                    {"bucketId": bucket, "accessKeyId": key, "permissions": permissions},
                )
                record_activity(
                    "bucket.allow" if payload.get("allow", True) else "bucket.deny",
                    f"{bucket} / {key}",
                    detail=json.dumps(permissions, sort_keys=True),
                    address=self.address_string(),
                )
                return self.reply_json(
                    {
                        "ok": True,
                        "result": result,
                        "bucketId": bucket,
                        "accessKeyId": key,
                        "permissions": permissions,
                    }
                )
        except GarageError as error:
            return self.reply_json({"error": error.message}, error.status)
        self.reply_json({"error": "Not found"}, 404)


def openapi_spec() -> dict:
    """Hand-written so the documented contract cannot silently drift from a
    generator's guesses; every path below is implemented in Handler."""
    json_body = {
        "required": True,
        "content": {"application/json": {"schema": {"type": "object"}}},
    }
    ok = {"200": {"description": "Success"}}
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Garage admin panel API",
            "version": "2.2.1",
            "description": (
                "Sign in with the panel form for a session cookie, or send "
                "`Authorization: Bearer <api key>` for scripts. Create keys in "
                "the panel's API keys section; the token is shown only once."
            ),
        },
        "servers": [{"url": "/"}],
        "components": {
            "securitySchemes": {
                "apiKey": {"type": "http", "scheme": "bearer"},
                "session": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": COOKIE_NAME,
                },
            }
        },
        "security": [{"apiKey": []}, {"session": []}],
        "paths": {
            "/api/overview": {
                "get": {
                    "summary": "Cluster status, active and archived buckets, backup ages, public paths, sign-ins",
                    "responses": ok,
                }
            },
            "/api/bucket/objects": {
                "get": {
                    "summary": "List one folder level in an active bucket",
                    "responses": ok,
                }
            },
            "/api/bucket/download": {
                "get": {
                    "summary": "Download one object from an active bucket",
                    "responses": ok,
                }
            },
            "/api/bucket/upload": {
                "post": {
                    "summary": "Upload one base64-encoded object using the configured browser write key",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/bucket/delete": {
                "post": {
                    "summary": "Delete one confirmed object",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/bucket/rename": {
                "post": {
                    "summary": "Rename one confirmed object using S3 copy/delete",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/keys": {
                "get": {
                    "summary": "Report that S3 access keys are locked",
                    "responses": ok,
                },
                "post": {
                    "summary": "Create an S3 access key (secret returned once)",
                    "requestBody": json_body,
                    "responses": ok,
                },
            },
            "/api/keys/reveal": {
                "post": {
                    "summary": "Reveal S3 access keys after re-entering the panel password",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/keys/delete": {
                "post": {
                    "summary": "Delete a Garage access key after exact-ID confirmation",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/buckets": {
                "post": {
                    "summary": "Create a bucket",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/buckets/name": {
                "post": {
                    "summary": "Set or clear a persistent friendly bucket name",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/buckets/archive": {
                "post": {
                    "summary": "Soft-delete a bucket for the configured archive period",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/buckets/restore": {
                "post": {
                    "summary": "Restore an archived bucket before purge",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/cloudflared/update": {
                "post": {
                    "summary": "Update and restart the optional Cloudflared service",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/restic/password": {
                "post": {
                    "summary": "Store an encrypted password for a detected Restic repository",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/restic/check": {
                "post": {
                    "summary": "Run a Restic health check for a detected repository",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/grant": {
                "post": {
                    "summary": "Grant or deny a key read/write/owner on a bucket",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
            "/api/apikeys": {
                "get": {
                    "summary": "List panel API keys with last-used timestamps",
                    "responses": ok,
                },
                "post": {
                    "summary": "Create a panel API key (token returned once)",
                    "requestBody": json_body,
                    "responses": ok,
                },
            },
            "/api/apikeys/revoke": {
                "post": {
                    "summary": "Revoke a panel API key by id",
                    "requestBody": json_body,
                    "responses": ok,
                }
            },
        },
    }


DOCS_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>API · Garage admin</title>
<link rel="stylesheet" href="/static/swagger-ui.css">
<style>body{margin:0}#bar{padding:10px 16px;background:#17222f;color:#eef3f8;font-family:system-ui,sans-serif;font-size:14px}
#bar a{color:#8dc8ff}</style>
</head><body>
<div id="bar">Garage admin API · <a href="/">back to panel</a> · requests below use your current session; scripts should send <code>Authorization: Bearer &lt;api key&gt;</code></div>
<div id="swagger"></div>
<script src="/static/swagger-ui-bundle.js"></script>
<script>
 window.ui = SwaggerUIBundle({url: "/openapi.json", dom_id: "#swagger", deepLinking: true,
   presets: [SwaggerUIBundle.presets.apis], layout: "BaseLayout", tryItOutEnabled: true,
   requestInterceptor: (request) => { request.credentials = "same-origin"; return request; }});
</script>
</body></html>"""

LOGIN_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · Garage admin</title>
<style>
 :root{color-scheme:dark;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
 *{box-sizing:border-box}
 body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1119;color:#e8eef5}
 form{width:min(380px,92vw);background:#121a26;border:1px solid #ffffff14;border-radius:14px;padding:30px 28px 26px;box-shadow:0 18px 50px #00000066}
 .brand{display:flex;align-items:center;gap:10px;margin-bottom:2px}
 h1{font-size:19px;margin:0;letter-spacing:-.01em;font-weight:700}
 .muted{color:#8ea0b3;font-size:13px;line-height:1.5}
 label{display:block;margin-top:16px;font-size:12.5px;color:#8ea0b3;font-weight:600;letter-spacing:.02em}
 input{width:100%;margin-top:6px;padding:11px 13px;border-radius:9px;border:1px solid #ffffff22;background:#0c1420;color:#e8eef5;font-size:15px;outline:none;transition:border-color .15s,box-shadow .15s}
 input:focus{border-color:#4a90e2;box-shadow:0 0 0 3px #347ed42e}
 .remember{display:flex;align-items:center;gap:8px;margin-top:16px;font-size:13.5px;color:#b9c7d6}
 .remember input{width:auto;margin:0;accent-color:#4a90e2}
 button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:9px;background:#4a90e2;color:#fff;font-weight:700;font-size:15px;cursor:pointer;transition:background .15s}
 button:hover{background:#5da1ef}
 .err{margin-top:14px;color:#ff9c9c;font-weight:600;font-size:13.5px;min-height:1em}
</style></head><body>
<form method="post" action="/login">
  <div class="brand">
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 8.5 12 4l8 4.5v7L12 20l-8-4.5v-7Z" stroke="#4a90e2" stroke-width="1.7" stroke-linejoin="round"/><path d="M4 8.5 12 13l8-4.5M12 13v7" stroke="#4a90e2" stroke-width="1.7" stroke-linejoin="round"/></svg>
    <h1>Garage admin</h1>
  </div>
  <div class="muted">Private access required.</div>
  <label>Username<input name="user" autocomplete="username" autofocus></label>
  <label>Password<input name="password" type="password" autocomplete="current-password"></label>
  <label class="remember"><input type="checkbox" name="remember" value="1"> Remember me for ${REMEMBER_DAYS}</label>
  <button type="submit">Sign in</button>
  <div class="err">{{message}}</div>
</form>
</body></html>"""

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Garage admin</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none'%3E%3Cpath d='M4 8.5 12 4l8 4.5v7L12 20l-8-4.5v-7Z' stroke='%234a90e2' stroke-width='1.7' stroke-linejoin='round'/%3E%3Cpath d='M4 8.5 12 13l8-4.5M12 13v7' stroke='%234a90e2' stroke-width='1.7' stroke-linejoin='round'/%3E%3C/svg%3E">
<meta name="theme-color" content="#0a0f16">
<style>
 :root{
   --bg:#0a0f16; --rail:#0d141d; --surface:#111926; --surface-2:#0c1420;
   --line:#ffffff12; --line-strong:#ffffff24;
   --text:#e6edf4; --muted:#8b9db1; --faint:#5c7085;
   --accent:#4a90e2; --accent-soft:#4a90e21f; --accent-hover:#5da1ef;
   --ok:#3fd68f; --warn:#f1a24b; --bad:#ff767e;
   --radius:14px; --radius-sm:10px;
   color-scheme:dark;
   font-family:system-ui,-apple-system,"Segoe UI",sans-serif;
 }
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--text);font-size:14px;line-height:1.45;display:flex;min-height:100vh}

 /* ================= sidebar rail ================= */
 .rail{position:fixed;inset:0 auto 0 0;width:232px;background:var(--rail);border-right:1px solid var(--line);display:flex;flex-direction:column;z-index:20}
 .brand{display:flex;align-items:center;gap:10px;padding:18px 18px 14px}
 .brand h1{font-size:16px;margin:0;font-weight:700;letter-spacing:-.01em}
 .brand .sub{color:var(--faint);font-size:11px;margin-top:1px}
 nav{flex:1;padding:6px 10px;display:flex;flex-direction:column;gap:2px;overflow-y:auto}
 .nav-label{color:var(--faint);font-size:10.5px;text-transform:uppercase;letter-spacing:.09em;font-weight:700;padding:14px 10px 5px}
 .nav-btn{display:flex;align-items:center;gap:10px;padding:9px 11px;border-radius:var(--radius-sm);background:transparent;border:0;color:var(--muted);font:inherit;font-weight:600;font-size:13.5px;cursor:pointer;text-align:left;width:100%;transition:background .12s,color .12s}
 .nav-btn svg{flex:0 0 17px;opacity:.85}
 .nav-btn:hover{background:#ffffff08;color:var(--text)}
 .nav-btn.active{background:var(--accent-soft);color:#bcd7f5}
 .nav-btn .badge{margin-left:auto;background:var(--warn);color:#20150a;font-size:10.5px;font-weight:800;border-radius:99px;padding:1px 7px}
 .rail-foot{padding:12px 14px;border-top:1px solid var(--line);display:flex;flex-direction:column;gap:8px}
 .rail-foot a{color:var(--muted);font-size:12.5px;text-decoration:none;display:flex;gap:8px;align-items:center}
 .rail-foot a:hover{color:var(--text)}

 /* ================= main column ================= */
 .content{flex:1;margin-left:232px;min-width:0;display:flex;flex-direction:column}
 .topbar{position:sticky;top:0;z-index:15;background:#0a0f16e8;backdrop-filter:blur(8px);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;padding:11px 26px}
 .topbar h2{font-size:15px;margin:0;font-weight:650}
 .topbar .spacer{flex:1}
 .refreshed{color:var(--faint);font-size:11.5px}
 main{width:auto;max-width:1160px;margin:auto;padding:22px 26px 60px}

 /* views */
 .view{display:none}
 .view.active{display:block}

 /* ================= cards & stats ================= */
 .summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:16px}
 .stat{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px}
 .stat-label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em;font-weight:650}
 .stat-value{font-size:23px;font-weight:750;margin-top:3px;font-variant-numeric:tabular-nums}
 section{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:18px;margin-bottom:14px}
 .section-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:10px}
 .section-head h2,.section-head h3{margin:0;font-size:15px;font-weight:650}
 .section-head p{margin:3px 0 0;color:var(--muted);font-size:13px}
 .settings-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
 .setting{padding:11px 12px;border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--surface-2);min-width:0}
 .setting-label{color:var(--muted);font-size:11px;margin-bottom:4px;font-weight:600}
 .setting code{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--text)}

 /* version card */
 .version-card{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
 .version-chip{display:inline-flex;align-items:center;gap:7px;background:var(--surface-2);border:1px solid var(--line-strong);border-radius:99px;padding:6px 14px;font-weight:700;font-size:13.5px;font-variant-numeric:tabular-nums}
 .version-chip .dot{width:8px;height:8px;border-radius:50%;background:var(--ok)}
 .version-chip.update .dot{background:var(--warn)}
 .version-note{color:var(--muted);font-size:12.5px}
 .version-arrow{color:var(--faint);font-size:16px}

 /* status */
 .status{display:inline-flex;align-items:center;gap:6px;font-weight:600}
 .status::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--muted)}
 .status.ok::before{background:var(--ok)}.status.bad::before{background:var(--bad)}

 /* tables */
 .table-scroll{overflow-x:auto;margin:0 -4px;padding:0 4px}
 #buckets{min-width:1500px}#archivedBuckets{min-width:760px}#browserFiles{min-width:760px}
 table{width:100%;border-collapse:collapse;font-size:13.5px}
 th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}
 th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.06em;position:sticky;top:0;background:var(--surface)}
 tbody tr:hover td{background:#ffffff06}
 #buckets th:last-child,#buckets td:last-child{position:sticky;right:0;background:var(--surface);box-shadow:-8px 0 10px -6px #00000080}
 code{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#79b8ec;word-break:break-all}

 /* controls */
 input,select{padding:9px 11px;border-radius:var(--radius-sm);border:1px solid var(--line-strong);background:var(--surface-2);color:var(--text);outline:none;transition:border-color .15s,box-shadow .15s}
 input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px #347ed42e}
 button{padding:9px 15px;border:0;border-radius:var(--radius-sm);background:var(--accent);color:#fff;font-weight:600;font-size:13.5px;cursor:pointer;transition:background .15s;font-family:inherit}
 button:hover{background:var(--accent-hover)}
 button.secondary{background:#33445a}button.secondary:hover{background:#40536d}
 button.danger{background:#b04a51}button.danger:hover{background:#c25a61}
 button.small{padding:4px 9px;font-size:11.5px;white-space:nowrap}
 button:disabled{opacity:.55;cursor:not-allowed}
 button:focus-visible,input:focus-visible,select:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
 .row{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin-top:12px}

 /* feedback */
 .notice{margin:0 0 14px;font-weight:600;color:var(--accent);min-height:20px;font-size:13.5px}
 .notice.err{color:var(--bad)}
 .secret{margin-top:10px;padding:13px;border-radius:var(--radius-sm);background:#0f2c1e;border:1px solid #35d07f59;display:grid;gap:4px}
 .err{color:var(--bad)}
 .tag{display:inline-block;white-space:nowrap;font-size:11px;padding:2px 8px;border-radius:99px;background:#2c3d52;color:#b9cbe0;margin:0 4px 4px 0}

 /* bucket widgets */
 .usage-widget{display:flex;align-items:center;gap:9px;min-width:180px}
 .usage-donut{width:46px;height:46px;flex:0 0 46px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--ok) var(--usage),#28374a 0);position:relative;box-shadow:0 0 0 1px var(--line)}
 .usage-donut::after{content:"";position:absolute;inset:6px;border-radius:50%;background:var(--surface)}
 .usage-donut strong{position:relative;z-index:1;font-size:9.5px;color:var(--text);font-variant-numeric:tabular-nums}
 .usage-copy{min-width:0}.usage-copy strong{display:block;font-size:13px}
 .usage-bar{height:4px;width:112px;margin-top:5px;border-radius:99px;background:var(--surface-2);overflow:hidden;border:1px solid var(--line)}
 .usage-bar span{display:block;height:100%;min-width:2px;border-radius:99px;background:linear-gradient(90deg,var(--ok),#79b8ec)}
 .usage-unknown .usage-donut{background:#28374a}
 .latest-file{display:flex;align-items:center;gap:6px;max-width:250px}
 .latest-file code{display:block;max-width:150px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .latest-clock{font-size:17px;line-height:1;flex:0 0 auto}
 .latest-clock.fresh{color:var(--ok)}.latest-clock.stale{color:var(--warn)}
 .latest-age{white-space:nowrap}
 .public-link{display:flex;gap:6px;align-items:flex-start;margin-bottom:6px;max-width:330px}
 .public-link code{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;word-break:normal}
 .bucket-open{background:transparent;color:#79b8ec;padding:0;text-align:left;font-weight:650;font-size:14px}
 .bucket-open:hover{text-decoration:underline;background:transparent}
 .bucket-name-actions{margin-top:5px}
 .browser-key{max-width:420px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .key-reveal{margin-top:10px}
 #grantStatus{margin-top:10px;min-height:20px}
 .activity-detail{max-width:360px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .danger-panel{margin:12px 0;padding:14px;border-radius:var(--radius-sm);background:#33202a;border:1px solid #e56d7854}
 .danger-panel strong{color:#ffb2b7}.danger-panel .row{margin-top:9px}
 .restic-card{padding:13px;border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--surface-2);margin-top:9px}
 .restic-card .row{margin-top:9px}.restic-card input{min-width:250px}
 .archive-row{background:#241d2b}.archive-row:hover td{background:#241d2b}
 .archive-actions{display:flex;gap:6px;flex-wrap:wrap}
 .empty{padding:14px 6px;color:var(--muted)}

 @media (max-width:900px){
   .rail{position:static;width:auto;max-width:100vw;flex-direction:row;flex-wrap:wrap;align-items:center;border-right:0;border-bottom:1px solid var(--line)}
   .brand{padding:12px 14px}
   nav{flex-direction:row;flex-wrap:wrap;overflow-x:auto;max-width:100%;padding:8px 10px}
   .nav-label,.rail-foot{display:none}
   .nav-btn{width:auto;white-space:nowrap}
   .content{margin-left:0;flex:1 1 auto}
   .topbar,main{padding-left:14px;padding-right:14px;width:auto;max-width:100%}
   .summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
   .settings-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
 }
 @media (max-width:600px){
   .summary-grid,.settings-grid{grid-template-columns:1fr}
 }
</style></head><body>

<aside class="rail">
  <div class="brand">
    <svg width="30" height="30" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 8.5 12 4l8 4.5v7L12 20l-8-4.5v-7Z" stroke="#4a90e2" stroke-width="1.7" stroke-linejoin="round"/><path d="M4 8.5 12 13l8-4.5M12 13v7" stroke="#4a90e2" stroke-width="1.7" stroke-linejoin="round"/></svg>
    <div><h1>Garage admin</h1><div class="sub">S3 control panel</div></div>
  </div>
  <nav aria-label="Sections">
    <div class="nav-label">Storage</div>
    <button class="nav-btn active" data-view="overview" type="button">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>
      Overview</button>
    <button class="nav-btn" data-view="buckets" type="button">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16l-1.5 12.5a2 2 0 0 1-2 1.5h-9a2 2 0 0 1-2-1.5L4 7Z"/><path d="M8 7a4 4 0 0 1 8 0"/></svg>
      Buckets</button>
    <button class="nav-btn" data-view="keys" type="button">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="8" cy="14" r="4"/><path d="m11 11 9-9m-4 4 3 3"/></svg>
      Access keys</button>
    <button class="nav-btn" data-view="apikeys" type="button">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M7 12h2m4 0h2m4 0-2-2m2 2-2 2M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Z"/></svg>
      API keys</button>
    <div class="nav-label">Cluster</div>
    <button class="nav-btn" data-view="cluster" type="button">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5V12m0 0-5.5 5M12 12l5.5 5"/></svg>
      Nodes &amp; versions</button>
    <button class="nav-btn" data-view="logs" type="button">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 5h16M4 12h10M4 19h7"/></svg>
      Activity</button>
    <div class="nav-label" id="archivedNavLabel" hidden>Archive</div>
    <button class="nav-btn" data-view="archived" id="archivedNavBtn" type="button" hidden>
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="4" width="18" height="4" rx="1"/><path d="M5 8v11a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8M10 12h4"/></svg>
      Archived buckets<span class="badge" id="archivedBadge" hidden>0</span></button>
  </nav>
  <div class="rail-foot">
    <span id="refreshedAt" class="refreshed"></span>
    <a href="/docs">API documentation</a>
    <a href="/logout">Sign out</a>
  </div>
</aside>

<div class="content">
<div class="topbar">
  <h2 id="viewTitle">Overview</h2>
  <div class="spacer"></div>
  <span id="endpoint" class="muted"></span>
</div>
<main>
<div id="notice" class="notice" role="status"></div>

<!-- ============ OVERVIEW ============ -->
<div class="view active" id="view-overview">
  <div id="summary" class="summary-grid"></div>

  <section>
    <div class="section-head"><div><h2>Garage version</h2><p class="muted">Running release compared with the newest upstream tag.</p></div></div>
    <div id="versionCard" class="version-card muted">Loading…</div>
  </section>

  <section>
    <div class="section-head"><div><h2>Connection settings</h2><p class="muted">Common S3-compatible settings for clients. Secrets stay hidden.</p></div></div>
    <div id="connectionSettings" class="settings-grid"></div>
  </section>

  <section id="cloudflaredSection" hidden>
    <div class="section-head"><div><h2>Cloudflared tunnel</h2><p class="muted">Optional tunnel status. Updating restarts the Garage tunnel briefly.</p></div><button id="updateCloudflared" class="secondary">Update Cloudflared</button></div>
    <div id="cloudflaredStatus" class="muted">Loading…</div>
  </section>

  <section id="resticSection" hidden>
    <div class="section-head"><div><h2>Restic health checks</h2><p class="muted">Repositories are detected from their object layout. Checks run only on request.</p></div></div>
    <div id="resticChecks"></div>
  </section>
</div>

<!-- ============ BUCKETS ============ -->
<div class="view" id="view-buckets">
  <section>
    <div class="section-head"><div><h2>Active buckets</h2><p class="muted">Click a bucket name to browse its files. Hover a friendly name to see the real Garage name. Archive hides a bucket immediately; its data stays for the grace period before purge.</p></div><button id="showArchive" class="danger">Archive bucket…</button></div>
    <div id="archivePanel" class="danger-panel" hidden>
      <strong>Archive a bucket</strong>
      <div id="archiveHint" class="muted">Type the exact bucket name manually. Nothing is deleted until the grace period ends.</div>
      <div class="row"><input id="archiveName" placeholder="type exact bucket name" autocomplete="off" spellcheck="false"><button id="confirmArchive" class="danger">Archive</button><button id="cancelArchive" class="secondary">Cancel</button></div>
    </div>
    <div class="table-scroll"><table id="buckets"><thead><tr><th>Name</th><th>Objects</th><th>Size</th><th>Usage</th><th>Latest file</th><th>Newest backup</th><th>Oldest backup</th><th>Public path</th><th>Keys</th><th>Actions</th></tr></thead><tbody></tbody></table></div>
    <div id="ageNote" class="muted"></div>
    <div class="row">
      <input id="bucketName" placeholder="new-bucket-name" autocomplete="off" spellcheck="false" aria-label="New bucket name">
      <button id="createBucket">Create bucket</button>
    </div>
  </section>

  <section id="browserSection" hidden>
    <div class="section-head"><div><h2>Bucket browser</h2><p id="browserHint" class="muted">Select a bucket to browse its objects.</p></div><button id="closeBrowser" class="secondary">Close browser</button></div>
    <div id="browserStatus" class="status muted">Select a bucket to begin.</div>
    <div class="row">
      <button id="browserUp" class="secondary" disabled>↑ Up</button>
      <button id="browserRefresh" class="secondary">Refresh</button>
      <input id="browserUpload" type="file" aria-label="Choose a file to upload">
      <button id="browserUploadButton" disabled>Upload here</button>
    </div>
    <div id="browserPath" class="muted"></div>
    <div class="table-scroll"><table id="browserFiles"><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Actions</th></tr></thead><tbody></tbody></table></div>
    <div class="row"><button id="browserNext" class="secondary" hidden>Next page</button></div>
  </section>
</div>

<!-- ============ ARCHIVED ============ -->
<div class="view" id="view-archived">
  <section id="archivedSection">
    <div class="section-head"><div><h2>Archived buckets</h2><p class="muted">Hidden from active views. They are purged automatically when the countdown reaches zero.</p></div></div>
    <div class="table-scroll"><table id="archivedBuckets"><thead><tr><th>Name</th><th>Archived</th><th>Deletes in</th><th>Snapshot</th><th>Status</th><th>Actions</th></tr></thead><tbody></tbody></table></div>
    <div id="restorePanel" class="danger-panel" hidden>
      <strong>Restore an archived bucket</strong>
      <div id="restoreHint" class="muted">Type the exact archived bucket name manually.</div>
      <div class="row"><input id="restoreName" placeholder="type exact bucket name" autocomplete="off" spellcheck="false"><button id="confirmRestore">Restore bucket</button><button id="cancelRestore" class="secondary">Cancel</button></div>
    </div>
  </section>
</div>

<!-- ============ KEYS ============ -->
<div class="view" id="view-keys">
  <section>
    <div class="section-head"><div><h2>Access keys</h2><p class="muted">All Garage keys are listed here. Secrets stay masked until you press "View keys" and re-enter the panel password.</p></div></div>
    <table id="keys"><thead><tr><th>Name</th><th>Access key ID</th><th>Secret access key</th><th>Created</th><th>Actions</th></tr></thead><tbody><tr><td colspan="5" class="muted">Loading keys…</td></tr></tbody></table>
    <div class="row">
      <input id="keyName" placeholder="new-key-name" autocomplete="off" spellcheck="false" aria-label="New key name">
      <button id="createKey">Create key</button>
      <button id="revealKeys" class="secondary">View keys…</button>
      <button id="hideKeys" class="secondary" hidden>Hide keys</button>
    </div>
    <div id="keyReveal" class="row key-reveal" hidden>
      <input id="keyPassword" type="password" placeholder="panel password" autocomplete="current-password" aria-label="Panel password">
      <button id="confirmReveal">View keys</button>
    </div>
    <div id="keyDeletePanel" class="danger-panel" hidden>
      <strong>Delete a Garage access key</strong>
      <div id="keyDeleteHint" class="muted">Type the exact access key ID manually. This immediately revokes the key everywhere.</div>
      <div class="row"><input id="keyDeleteId" placeholder="type exact access key ID" autocomplete="off" spellcheck="false"><button id="confirmKeyDelete" class="danger">Delete key</button><button id="cancelKeyDelete" class="secondary">Cancel</button></div>
    </div>
    <div id="secretBox"></div>
  </section>

  <section>
    <div class="section-head"><div><h2>Grant a key access to a bucket</h2><p class="muted">Applies permissions to an existing Garage account on an existing bucket.</p></div></div>
    <div class="row">
      <select id="grantBucket" aria-label="Bucket"><option value="">Select bucket…</option></select>
      <select id="grantKey" aria-label="Account"><option value="">Select account…</option></select>
      <label class="muted"><input type="checkbox" id="permRead" checked> read</label>
      <label class="muted"><input type="checkbox" id="permWrite" checked> write</label>
      <label class="muted"><input type="checkbox" id="permOwner"> owner</label>
      <button id="grant" class="secondary" disabled>Apply access</button>
    </div>
    <div id="grantStatus" class="status muted">Select a bucket, account, and permissions.</div>
  </section>
</div>

<!-- ============ API KEYS ============ -->
<div class="view" id="view-apikeys">
  <section>
    <div class="section-head"><div><h2>API keys</h2><p class="muted">For scripts. Send <code>Authorization: Bearer &lt;token&gt;</code>. The token is shown once.</p></div></div>
    <table id="apikeys"><thead><tr><th>Name</th><th>Created</th><th>Last used</th><th>From</th><th></th></tr></thead><tbody></tbody></table>
    <div class="row">
      <input id="apiKeyName" placeholder="script name" autocomplete="off" spellcheck="false" aria-label="New API key name">
      <button id="createApiKey">Create API key</button>
      <a class="plainlink" href="/docs" style="color:var(--accent);text-decoration:none;font-weight:600;align-self:center">Swagger docs</a>
    </div>
    <div id="apiKeyBox"></div>
  </section>
</div>

<!-- ============ CLUSTER ============ -->
<div class="view" id="view-cluster">
  <section>
    <div class="section-head"><div><h2>Nodes</h2><p class="muted">Live cluster membership and disk headroom.</p></div></div>
    <div id="cluster" class="muted">Loading…</div>
  </section>
</div>

<!-- ============ LOGS ============ -->
<div class="view" id="view-logs">
  <section>
    <div class="section-head"><div><h2>Recent sign-ins</h2></div></div>
    <table id="signins"><thead><tr><th>When</th><th>Result</th><th>User</th><th>From</th></tr></thead><tbody></tbody></table>
  </section>
  <section>
    <div class="section-head"><div><h2>Activity log</h2><p class="muted">Recent bucket, key, grant, Cloudflared, Restic, and API-key actions. Secrets are never written here.</p></div></div>
    <div class="table-scroll"><table id="activity"><thead><tr><th>When</th><th>Action</th><th>Target</th><th>Result</th><th>From</th><th>Detail</th></tr></thead><tbody></tbody></table></div>
  </section>
</div>
</main>

<script>
(() => {
 "use strict";
 const $ = (id) => document.getElementById(id);
 const notice = (text, bad) => { const n = $("notice"); n.textContent = text || ""; n.className = "notice" + (bad ? " err" : ""); };
 const text = (v) => String(v ?? "");
 const el = (tag, cls, value) => { const e = document.createElement(tag); if (cls) e.className = cls; if (value !== undefined) e.textContent = text(value); return e; };
 async function api(path, options) {
   const response = await fetch(path, Object.assign({cache: "no-store", headers: {"Content-Type": "application/json"}}, options || {}));
   const data = await response.json().catch(() => ({}));
   if (response.status === 401) { location.href = "/login"; throw new Error("Session expired."); }
   if (!response.ok) throw new Error(data.error || ("Request failed (" + response.status + ")"));
   return data;
 }
 function stamp(v) { return v ? new Date(v).toLocaleString() : "—"; }
 function ago(v) {
   if (!v) return "—";
   const seconds = (Date.now() - new Date(v).getTime()) / 1000;
   if (seconds < 0) return "just now";
   const units = [["y", 31557600], ["mo", 2629800], ["d", 86400], ["h", 3600], ["m", 60]];
   for (const [label, size] of units) { if (seconds >= size) return Math.floor(seconds / size) + label + " ago"; }
   return "just now";
 }
 function bytes(v) {
   if (v === null || v === undefined) return "—";
   let size = Number(v); const units = ["B","KB","MB","GB","TB"];
   for (const unit of units) { if (size < 1024 || unit === "TB") return (unit === "B" ? size.toFixed(0) : size.toFixed(1)) + " " + unit; size /= 1024; }
   return "—";
 }
 function percent(v) {
   if (v === null || v === undefined || Number.isNaN(Number(v))) return "—";
   const value = Number(v);
   if (value > 0 && value < 0.01) return "<0.01%";
   return (value < 1 ? value.toFixed(2) : value.toFixed(1)) + "%";
 }
 function shortFilename(key) {
   const full = String(key || "");
   const slash = full.lastIndexOf("/");
   const filename = slash >= 0 ? full.slice(slash + 1) : full;
   return filename.length > 34 ? "…" + filename.slice(-33) : filename;
 }
 function latestIsFresh(value) {
   if (!value) return false;
   const timestamp = new Date(value).getTime();
   return Number.isFinite(timestamp) && (Date.now() - timestamp) < 24 * 60 * 60 * 1000;
 }
 async function copyText(value) {
   if (navigator.clipboard && window.isSecureContext) {
     await navigator.clipboard.writeText(value);
     return;
   }
   const input = document.createElement("textarea");
   input.value = value; input.setAttribute("readonly", "");
   input.style.position = "fixed"; input.style.opacity = "0";
   document.body.append(input); input.select();
   if (!document.execCommand("copy")) throw new Error("Copy was blocked by the browser.");
   input.remove();
 }
 function copyButton(value) {
   const button = el("button", "secondary small", "Copy");
   button.type = "button";
   button.addEventListener("click", async () => {
     try { await copyText(value); notice("Copied public link."); }
     catch (error) { notice(error.message, true); }
   });
   return button;
 }
 function publicLink(value) {
   const line = el("div", "public-link");
   line.append(el("code", "", value), copyButton(value));
   return line;
 }
 function renderConnectionSettings(data) {
   const settings = data.connectionSettings || {}, box = $("connectionSettings");
   box.replaceChildren();
   const values = [
     ["S3 endpoint", settings.s3Endpoint || "Not configured"],
     ["Region", settings.region || "Not configured"],
     ["Access key ID", settings.accessKeyId || "Not configured"],
     ["Path-style URL", settings.pathStyleTemplate || "Public endpoint not configured"],
     ["Credentials", settings.credentialsConfigured ? "Read key configured · secret hidden" : "Not configured"],
     ["File changes", settings.browserWriteEnabled ? "Read/write browser key configured" : "Read-only browser"],
   ];
   values.forEach(([label, value]) => {
     const card = el("div", "setting");
     card.append(el("div", "setting-label", label), el("code", "", value));
     box.append(card);
   });
 }
 function setGrantStatus(message, kind) {
   const status = $("grantStatus");
   status.textContent = message;
   status.className = "status " + (kind || "muted");
 }
 function renderGrantOptions(data) {
   const bucketSelect = $("grantBucket"), keySelect = $("grantKey");
   const previousBucket = bucketSelect.value, previousKey = keySelect.value;
   bucketSelect.replaceChildren(el("option", "", "Select bucket…"));
   (data.buckets || []).forEach(bucket => {
     const option = el("option", "", (bucket.aliases[0] || "(no alias)") + " · " + bucket.id.slice(0, 16) + "…");
     option.value = bucket.id;
     bucketSelect.append(option);
   });
   keySelect.replaceChildren(el("option", "", "Select account…"));
   (data.accessKeys || []).forEach(account => {
     const option = el("option", "", account.name + " · " + account.id + (account.expired ? " · expired" : ""));
     option.value = account.id;
     option.disabled = Boolean(account.expired);
     keySelect.append(option);
   });
   if ([...bucketSelect.options].some(option => option.value === previousBucket)) bucketSelect.value = previousBucket;
   if ([...keySelect.options].some(option => option.value === previousKey)) keySelect.value = previousKey;
   $("grant").disabled = !bucketSelect.value || !keySelect.value;
 }
 function renderActivity(entries) {
   const body = document.querySelector("#activity tbody");
   body.replaceChildren();
   (entries || []).forEach(entry => {
     const row = document.createElement("tr");
     row.append(el("td", "muted", stamp(entry.at)));
     row.append(el("td", "", entry.action));
     row.append(el("td", "", entry.target || "—"));
     row.append(el("td", entry.outcome === "ok" ? "" : "err", entry.outcome || "—"));
     row.append(el("td", "muted", entry.from || "—"));
     const detail = el("td", "muted activity-detail", entry.detail || "—");
     detail.title = entry.detail || "";
     row.append(detail);
     body.append(row);
   });
   if (!(entries || []).length) {
     const row = document.createElement("tr");
     const cell = el("td", "muted", "No activity recorded yet.");
     cell.colSpan = 6; row.append(cell); body.append(row);
   }
 }
 let browserBucket = "", browserPrefix = "", browserNextToken = "", browserFile = null, browserMaxUploadBytes = 0, browserCanWrite = false;
 function browserParent(prefix) {
   const trimmed = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
   const slash = trimmed.lastIndexOf("/");
   return slash >= 0 ? trimmed.slice(0, slash + 1) : "";
 }
 function browserObjectUrl(key) {
   return "/api/bucket/download?bucket=" + encodeURIComponent(browserBucket) + "&key=" + encodeURIComponent(key);
 }
 function setBrowserStatus(message, kind) {
   const status = $("browserStatus");
   status.textContent = message;
   status.className = "status " + (kind || "muted");
 }
 function renderBrowser(data) {
   browserMaxUploadBytes = Number(data.maxUploadBytes || 0);
   const canWrite = Boolean(data.writeEnabled);
   browserCanWrite = canWrite;
   $("browserHint").textContent = canWrite
     ? "Browse, upload, download, rename, and delete objects. Uploads are limited to " + bytes(browserMaxUploadBytes) + "."
     : "Browse and download objects. File changes are disabled until a separate read/write browser key is configured.";
   setBrowserStatus(canWrite ? "File changes enabled" : "Read-only browser", canWrite ? "ok" : "muted");
   $("browserPath").textContent = data.bucket + "/" + (data.prefix || "");
   $("browserUp").disabled = !data.prefix;
   $("browserUploadButton").disabled = !canWrite || !browserFile;
   const body = document.querySelector("#browserFiles tbody");
   body.replaceChildren();
   (data.prefixes || []).forEach(prefix => {
     const row = document.createElement("tr");
     const name = el("td");
     const open = el("button", "bucket-open", "📁 " + prefix.slice(data.prefix.length));
     open.type = "button";
     open.addEventListener("click", () => { browserPrefix = prefix; browserNextToken = ""; loadBrowser(); });
     name.append(open); row.append(name);
     row.append(el("td", "muted", "folder"), el("td", "muted", "—"));
     const action = el("td", "muted", "Open folder"); row.append(action); body.append(row);
   });
   (data.objects || []).forEach(file => {
     const row = document.createElement("tr");
     const name = el("td");
     const code = el("code", "browser-key", file.key);
     code.title = file.key;
     name.append(code); row.append(name);
     row.append(el("td", "", bytes(file.size)), el("td", "muted", stamp(file.modified)));
     const actions = el("td", "archive-actions");
     const download = document.createElement("a");
     download.className = "secondary small"; download.textContent = "Download"; download.href = browserObjectUrl(file.key);
     download.setAttribute("download", file.key.split("/").pop());
     actions.append(download);
     if (canWrite) {
       const rename = el("button", "secondary small", "Rename");
       rename.addEventListener("click", async () => {
         const newKey = prompt("New object key", file.key);
         if (!newKey || newKey === file.key) return;
         try {
           await api("/api/bucket/rename", {method: "POST", body: JSON.stringify({bucket: browserBucket, key: file.key, newKey, confirmation: file.key})});
           notice("Renamed object."); loadBrowser();
         } catch (error) { setBrowserStatus(error.message, "bad"); notice(error.message, true); }
       });
       const remove = el("button", "danger small", "Delete");
       remove.addEventListener("click", async () => {
         if (!confirm("Delete object “" + file.key + "”? This cannot be undone.")) return;
         try {
           await api("/api/bucket/delete", {method: "POST", body: JSON.stringify({bucket: browserBucket, key: file.key, confirmation: file.key})});
           notice("Deleted object."); loadBrowser();
         } catch (error) { setBrowserStatus(error.message, "bad"); notice(error.message, true); }
       });
       actions.append(rename, remove);
     }
     row.append(actions); body.append(row);
   });
   if (!(data.prefixes || []).length && !(data.objects || []).length) {
     const row = document.createElement("tr");
     const cell = el("td", "muted", "This folder is empty."); cell.colSpan = 4; row.append(cell); body.append(row);
   }
   $("browserNext").hidden = !data.truncated || !data.nextToken;
   browserNextToken = data.nextToken || "";
 }
 async function loadBrowser(continuation) {
   if (!browserBucket) return;
   setBrowserStatus("Loading objects…", "muted");
   const params = new URLSearchParams({bucket: browserBucket, prefix: browserPrefix});
   if (continuation) params.set("continuation", continuation);
   try { renderBrowser(await api("/api/bucket/objects?" + params.toString())); }
   catch (error) { setBrowserStatus(error.message, "bad"); notice(error.message, true); }
 }
 function openBrowser(name) {
   browserBucket = name; browserPrefix = ""; browserNextToken = ""; browserFile = null;
   $("browserSection").hidden = false; $("browserUpload").value = ""; $("browserUploadButton").disabled = true;
   $("browserSection").scrollIntoView({behavior: "smooth", block: "start"});
   loadBrowser();
 }
 function closeBrowser() {
   browserBucket = ""; browserPrefix = ""; browserNextToken = ""; browserFile = null; browserCanWrite = false;
   $("browserSection").hidden = true; $("browserUpload").value = "";
 }
 function bytesToBase64(buffer) {
   const values = new Uint8Array(buffer); let binary = "";
   for (let start = 0; start < values.length; start += 0x8000) binary += String.fromCharCode(...values.subarray(start, start + 0x8000));
   return btoa(binary);
 }
 function renderCloudflared(data) {
   const cf = data.cloudflared || {}, section = $("cloudflaredSection"), box = $("cloudflaredStatus");
   section.hidden = !cf.enabled;
   if (!cf.enabled) return;
   box.replaceChildren();
   const status = el("div", "status " + (cf.active ? "ok" : "bad"), cf.active ? "Running" : "Not running");
   box.append(status);
   box.append(el("span", "muted", "  " + text(cf.version || "version unavailable") + " · " + text(cf.service || "service unavailable")));
   if (cf.started) box.append(el("div", "muted", "Started " + cf.started));
   if (cf.error) box.append(el("div", "err", cf.error));
 }
 function renderRestic(data) {
   const section = $("resticSection"), box = $("resticChecks");
   const entries = data.resticEnabled ? (data.buckets || []).filter(bucket => bucket.restic && bucket.restic.detected) : [];
   section.hidden = !entries.length;
   box.replaceChildren();
   entries.forEach(bucket => {
     const name = bucket.aliases[0] || bucket.id;
     const state = bucket.restic.lastCheck;
     const card = el("div", "restic-card");
     card.append(el("strong", "", name));
     const stateText = state ? (state.ok ? "Healthy" : "Failed") : (bucket.restic.passwordConfigured ? "Not checked" : "Password needed");
     card.append(el("span", "status " + (state && state.ok ? "ok" : state && !state.ok ? "bad" : ""), "  " + stateText));
     card.append(el("div", "muted", "Markers: " + (bucket.restic.markers || []).join(", ") + (bucket.restic.passwordSource ? " · password " + bucket.restic.passwordSource : " · password not configured")));
     if (state) {
       const resultLine = el("div", state.ok ? "muted" : "err", "Last check " + stamp(state.checkedAt) + " · " + (state.summary || "" ).slice(0, 180));
       resultLine.title = state.summary || "";
       card.append(resultLine);
     }
     const row = el("div", "row");
     const password = document.createElement("input");
     password.type = "password"; password.placeholder = bucket.restic.passwordConfigured ? "replace saved password" : "repository password"; password.autocomplete = "new-password";
     const save = el("button", "secondary", "Save password");
     save.addEventListener("click", async () => {
       if (!password.value) return notice("Enter the Restic repository password first.", true);
       try { await api("/api/restic/password", {method: "POST", body: JSON.stringify({bucket: name, password: password.value})}); password.value = ""; notice("Stored the encrypted Restic password for “" + name + "”."); refresh(); }
       catch (error) { notice(error.message, true); }
     });
     const check = el("button", "secondary", "Run health check");
     check.addEventListener("click", async () => {
       if (!confirm("Run a Restic health check for “" + name + "”? It may take a while.")) return;
       check.disabled = true;
       try {
         const result = await api("/api/restic/check", {method: "POST", body: JSON.stringify({bucket: name})});
         notice(result.ok ? "Restic check passed for “" + name + "”." : "Restic check failed for “" + name + "”.", !result.ok);
         refresh();
       } catch (error) { notice(error.message, true); }
       finally { check.disabled = false; }
     });
     row.append(password, save, check); card.append(row); box.append(card);
   });
 }
 function renderSummary(data) {
   const buckets = data.buckets || [], archived = data.archivedBuckets || [];
   const objectCount = buckets.reduce((total, bucket) => total + Number(bucket.objects || 0), 0);
   const byteCount = buckets.reduce((total, bucket) => total + Number(bucket.bytes || 0), 0);
   const summary = $("summary"); summary.replaceChildren();
   [["Active buckets", buckets.length], ["Objects", objectCount.toLocaleString()], ["Logical size", bytes(byteCount)], ["Archive queue", archived.length]].forEach(([label, value]) => {
     const card = el("div", "stat"); card.append(el("div", "stat-label", label), el("div", "stat-value", value)); summary.append(card);
   });
 }
function renderVersion(v) {
  const box = $("versionCard"); if (!box) return;
  box.replaceChildren();
  const chip = el("span", "version-chip");
  chip.append(el("span", "dot"));
  chip.append(el("strong", "", v.current ? "Garage " + v.current : "Version unknown"));
  box.append(chip);
  if (v.latest && v.current && v.updateAvailable) {
    chip.classList.add("update");
    box.append(el("span", "version-arrow", "→"));
    const next = el("span", "version-chip update");
    next.append(el("strong", "", v.latest + " available"));
    box.append(next);
    const link = document.createElement("a");
    link.href = "https://garagehq.deuxfleurs.fr/blog/"; link.target = "_blank"; link.rel = "noopener";
    link.className = "plainlink"; link.textContent = "Release notes";
    link.style.cssText = "color:var(--accent);text-decoration:none;font-weight:600;font-size:13px";
    box.append(link);
  } else if (v.latest && v.current) {
    box.append(el("span", "version-note", "Up to date with upstream."));
  }
  if (v.error) box.append(el("span", "err", v.error));
  else if (v.checkedAt) box.append(el("span", "version-note", "Checked " + ago(v.checkedAt) + "."));
}
function renderArchivedBadge(count) {
  const btn = $("archivedNavBtn"), badge = $("archivedBadge"), label = $("archivedNavLabel");
  if (!btn) return;
  btn.hidden = count === 0; label.hidden = count === 0;
  badge.hidden = count === 0; badge.textContent = String(count);
}
function openArchive(name) {
  $("archivePanel").hidden = false;
   $("archiveName").value = "";
   $("archiveHint").textContent = "Type “" + name + "” exactly to archive it for 60 days. Nothing is deleted now.";
   $("archiveName").focus();
 }
 async function editFriendlyBucketName(bucket) {
   const realName = (bucket.aliases || [])[0] || bucket.id;
   const current = bucket.friendlyName || "";
   const value = prompt(
     "Friendly display name for “" + realName + "”. Leave blank to show the real name.",
     current
   );
   if (value === null) return;
   try {
     await api("/api/buckets/name", {
       method: "POST",
       body: JSON.stringify({bucketId: bucket.id, friendlyName: value})
     });
     notice(value.trim() ? "Friendly bucket name saved." : "Friendly bucket name cleared.");
     refresh();
   } catch (error) { notice(error.message, true); }
 }
 function renderArchived(entries) {
   const section = $("archivedSection"), body = document.querySelector("#archivedBuckets tbody");
   body.replaceChildren();
   section.hidden = !(entries || []).length;
   (entries || []).forEach(entry => {
     const row = el("tr", "archive-row");
     const nameCell = el("td");
     const displayName = entry.friendlyName || entry.name;
     const name = el("span", "bucket-open", displayName);
     name.title = "Real Garage name: " + entry.name;
     nameCell.append(name);
     row.append(nameCell);
     row.append(el("td", "muted", stamp(entry.archivedAt)));
     row.append(el("td", "", entry.daysRemaining > 0 ? entry.daysRemaining + " days" : "due now"));
     row.append(el("td", "muted", (entry.objects ?? "—") + " objects · " + bytes(entry.bytes)));
     const status = el("td", entry.lastError ? "err" : "muted", entry.lastError ? "Purge retry pending" : "Waiting for grace period");
     if (entry.lastError) status.title = entry.lastError;
     row.append(status);
     const actions = el("td", "archive-actions");
     const restore = el("button", "secondary small", "Restore");
     restore.addEventListener("click", () => {
       $("restorePanel").hidden = false; $("restoreName").value = "";
       $("restoreHint").textContent = "Type “" + entry.name + "” exactly to restore it.";
       $("restoreName").focus();
     });
     actions.append(restore); row.append(actions); body.append(row);
   });
 }
 let accessKeyMetadata = [];   // always fetched: name/id/created, no secrets
 let keysRevealed = false;
 function secretCellFor(key) {
   const cell = el("td");
   if (keysRevealed && key.secretAvailable && key.secretAccessKey) {
     cell.append(el("code", "", key.secretAccessKey));
   } else if (!key.secretAvailable) {
     cell.append(el("span", "muted", "Unavailable — rotate this key"));
   } else {
     cell.append(el("code", "", "•".repeat(20)));
     cell.title = 'Press "View keys" and re-enter the panel password to show.';
   }
   return cell;
 }
 function renderKeys(entries) {
   const body = document.querySelector("#keys tbody"); body.replaceChildren();
   (entries || []).forEach(key => {
     const row = document.createElement("tr");
     row.append(el("td", "", key.name || "(unnamed)"));
     row.append(el("td", "", key.id));
     row.append(secretCellFor(key));
     const created = el("td", "muted", key.created + (key.expired ? " (expired)" : ""));
     row.append(created);
     const actions = el("td");
     const remove = el("button", "danger small", "Delete");
     remove.addEventListener("click", () => {
       keyDeleteTarget = key.id;
       $("keyDeleteId").value = "";
       $("keyDeleteHint").textContent = "Type “" + key.id + "” exactly to revoke this key immediately.";
       $("keyDeletePanel").hidden = false;
       $("keyDeleteId").focus();
     });
     actions.append(remove); row.append(actions);
     body.append(row);
   });
   if (!(entries || []).length) {
     const row = document.createElement("tr");
     const cell = el("td", "muted", "No Garage keys found."); cell.colSpan = 5; row.append(cell);
     body.append(row);
   }
 }
 function hideSecrets() {
   if (!accessKeyMetadata.length) return;
   renderKeys(accessKeyMetadata);
 }
 function setKeysVisibility(revealed) {
   keysRevealed = revealed;
   hideSecrets();
   $("hideKeys").hidden = !revealed || !accessKeyMetadata.some(key => key.secretAvailable);
   $("revealKeys").hidden = revealed;
   const revealRow = $("keyReveal");
   if (revealed) revealRow.hidden = true;
}
async function refresh() {
  try {
    const data = await api("/api/overview");
    const stampEl = $("refreshedAt");
    if (stampEl) stampEl.textContent = "refreshed " + new Date().toLocaleTimeString();
    renderSummary(data);
    renderVersion(data.garageVersion || {});
    renderConnectionSettings(data);
    renderGrantOptions(data);
    renderCloudflared(data);
    renderRestic(data);
     const cluster = data.cluster || {};
     const box = $("cluster"); box.replaceChildren();
     if (cluster.error) { box.append(el("div", "err", cluster.error)); }
     else {
       (cluster.nodes || []).forEach(node => {
         const line = el("div");
         line.append(el("strong", "", node.hostname || node.id));
         line.append(el("span", "muted", "  " + (node.up ? "up" : "down") + " · capacity " + text(node.capacity) + " · disk " + text(node.available) + " free of " + text(node.total)));
         box.append(line);
       });
       box.append(el("div", "muted", "layout version " + text(cluster.layoutVersion)));
     }
     const body = document.querySelector("#buckets tbody"); body.replaceChildren();
     (data.buckets || []).forEach(bucket => {
       const row = document.createElement("tr");
       const nameCell = el("td");
       const bucketAlias = bucket.aliases[0] || "";
       const displayName = bucket.friendlyName || bucketAlias || "(no alias)";
       if (bucketAlias) {
         const open = el("button", "bucket-open", displayName);
         open.type = "button";
         open.title = "Real Garage name: " + bucketAlias + " · Open bucket browser";
         open.addEventListener("click", () => openBrowser(bucketAlias));
         nameCell.append(open);
       } else {
         const missing = el("span", "bucket-open", displayName);
         missing.title = "Garage bucket ID: " + bucket.id;
         nameCell.append(missing);
       }
       const nameAction = el("div", "bucket-name-actions");
       const nameButton = el("button", "secondary small", bucket.friendlyName ? "Edit name" : "Set friendly name");
       nameButton.type = "button";
       nameButton.addEventListener("click", () => editFriendlyBucketName(bucket));
       nameAction.append(nameButton);
       nameCell.append(nameAction);
       nameCell.append(el("code", "", bucket.id.slice(0, 16) + "…"));
       if (bucket.error) nameCell.append(el("div", "err", bucket.error));
       row.append(nameCell);
       row.append(el("td", "", bucket.objects === null ? "—" : bucket.objects));
       row.append(el("td", "", bytes(bucket.bytes)));
       const usageCell = el("td");
       if (bucket.usagePercent !== null && bucket.usagePercent !== undefined) {
         const value = Math.min(100, Math.max(0, Number(bucket.usagePercent)));
         const widget = el("div", "usage-widget");
         const donut = el("div", "usage-donut");
         donut.style.setProperty("--usage", value + "%");
         donut.title = percent(bucket.usagePercent) + " of configured Garage capacity";
         donut.append(el("strong", "", percent(bucket.usagePercent)));
         const copy = el("div", "usage-copy");
         copy.append(el("strong", "", bytes(bucket.bytes)));
         const bar = el("div", "usage-bar");
         const barFill = document.createElement("span");
         barFill.style.width = value + "%";
         bar.append(barFill); copy.append(bar);
         copy.append(el("div", "muted", "of " + bytes((data.cluster || {}).capacityBytes)));
         widget.append(donut, copy); usageCell.append(widget);
       } else {
         const widget = el("div", "usage-widget usage-unknown");
         const donut = el("div", "usage-donut"); donut.append(el("strong", "", "—"));
         widget.append(donut, el("span", "muted", "Usage unavailable")); usageCell.append(widget);
       }
       row.append(usageCell);
       const latestCell = el("td");
       if (bucket.latestError) latestCell.append(el("span", "err", bucket.latestError.slice(0, 50)));
       else if (bucket.latest === null) latestCell.append(el("span", "muted", "S3 listing off"));
       else if (!(bucket.latest || []).length) latestCell.append(el("span", "muted", "none"));
       else {
         const file = bucket.latest[0];
         const fresh = latestIsFresh(file.modified);
         const fileLine = el("div", "latest-file");
         const clock = el("span", "latest-clock " + (fresh ? "fresh" : "stale"), "◷");
         clock.title = fresh ? "Updated within the last 24 hours" : "Updated more than 24 hours ago";
         clock.setAttribute("aria-label", clock.title);
         const filename = el("code", "", shortFilename(file.key));
         filename.title = file.key;
         fileLine.append(clock, filename, el("span", "muted latest-age", ago(file.modified)));
         latestCell.append(fileLine);
       }
       row.append(latestCell);
       const backup = bucket.backup;
       const newestCell = el("td"), oldestCell = el("td");
       if (!backup) { newestCell.append(el("span", "muted", "—")); oldestCell.append(el("span", "muted", "—")); }
       else if (backup.error) { newestCell.append(el("span", "err", backup.error.slice(0, 40))); oldestCell.append(el("span", "muted", "—")); }
       else {
         newestCell.append(el("div", "", ago(backup.newest)));
         newestCell.append(el("div", "muted", stamp(backup.newest)));
         oldestCell.append(el("div", "", ago(backup.oldest)));
         oldestCell.append(el("div", "muted", stamp(backup.oldest) + (backup.truncated ? " (scan capped)" : "")));
       }
       row.append(newestCell); row.append(oldestCell);
       const pub = bucket.public || {};
       const pubCell = el("td");
       if (pub.path_style) pubCell.append(publicLink(pub.path_style));
       if (!pub.path_style) pubCell.append(el("span", "muted", "—"));
       row.append(pubCell);
       const keyCell = el("td");
       (bucket.keys || []).forEach(key => {
         const perms = [key.owner ? "owner" : null, key.read ? "r" : null, key.write ? "w" : null].filter(Boolean).join("/");
         keyCell.append(el("span", "tag", (key.name || key.id) + (perms ? " " + perms : "")));
       });
       if (!(bucket.keys || []).length) keyCell.append(el("span", "muted", "none"));
       row.append(keyCell);
       const actionCell = el("td");
       const bucketName = bucket.aliases[0];
       if (bucketName) {
         const archive = el("button", "danger small", "Archive");
         archive.addEventListener("click", () => openArchive(bucketName));
         actionCell.append(archive);
       } else actionCell.append(el("span", "muted", "—"));
       row.append(actionCell);
       body.append(row);
     });
     renderArchived(data.archivedBuckets || []);
     renderArchivedBadge((data.archivedBuckets || []).length);
     const note = $("ageNote");
     if (!data.backupAges) note.textContent = "Backup ages are off — set S3_ACCESS_KEY and S3_SECRET_KEY in garage-panel.env to enable them.";
     else if ((data.backupBuckets || []).length) note.textContent = "Backup ages shown for: " + data.backupBuckets.join(", ");
     else note.textContent = "Backup ages shown for every readable bucket (set BACKUP_BUCKETS to narrow this).";
     const endpointBox = $("endpoint");
     const endpoint = data.endpoint || {};
     endpointBox.textContent = endpoint.public
       ? ("S3 endpoint " + endpoint.public + "  ·  path-style URLs only")
       : "Set S3_PUBLIC_ENDPOINT in garage-panel.env to show public bucket paths.";
     const signinBody = document.querySelector("#signins tbody"); signinBody.replaceChildren();
     (data.signins || []).forEach(entry => {
       const row = document.createElement("tr");
       row.append(el("td", "muted", new Date(entry.at).toLocaleString()));
       row.append(el("td", entry.outcome === "ok" ? "" : "err", entry.outcome));
       row.append(el("td", "", entry.user));
       row.append(el("td", "muted", entry.from));
       signinBody.append(row);
     });
     if (!(data.signins || []).length) signinBody.append(el("tr")).append(el("td", "muted", "No sign-ins recorded yet."));
     renderActivity(data.activity || []);
     const apiKeys = await api("/api/apikeys");
     const apiBody = document.querySelector("#apikeys tbody"); apiBody.replaceChildren();
     (apiKeys.keys || []).forEach(entry => {
       const row = document.createElement("tr");
       row.append(el("td", "", entry.name));
       row.append(el("td", "muted", stamp(entry.created)));
       row.append(el("td", "", entry.last_used ? ago(entry.last_used) : "never"));
       row.append(el("td", "muted", entry.last_used_from || "—"));
       const actions = el("td");
       const revoke = el("button", "secondary", "Revoke");
       revoke.addEventListener("click", async () => {
         if (!confirm("Revoke API key “" + entry.name + "”?")) return;
         try { await api("/api/apikeys/revoke", {method: "POST", body: JSON.stringify({id: entry.id})}); notice("Revoked “" + entry.name + "”."); refresh(); }
         catch (error) { notice(error.message, true); }
       });
       actions.append(revoke); row.append(actions);
       apiBody.append(row);
     });
     if (!(apiKeys.keys || []).length) { const r = document.createElement("tr"); r.append(el("td", "muted", "No API keys yet — create one above.")); apiBody.append(r); }
     // Always show access key metadata (secrets masked until reveal).
     await api("/api/keys").then(keysData => {
       if (keysData.error) throw new Error(keysData.error);
       accessKeyMetadata = keysData.keys || [];
       renderKeys(accessKeyMetadata);
       setKeysVisibility(keysRevealed && accessKeyMetadata.some(key => key.secretAvailable));
     });
     $("keysLoadingNote")?.remove();
   } catch (error) { notice(error.message, true); }
 }
 $("showArchive").addEventListener("click", () => {
   $("archivePanel").hidden = false;
   $("archiveHint").textContent = "Type the exact bucket name manually. Nothing is deleted until the 60-day grace period ends.";
   $("archiveName").value = ""; $("archiveName").focus();
 });
 $("cancelArchive").addEventListener("click", () => { $("archivePanel").hidden = true; });
 $("confirmArchive").addEventListener("click", async () => {
   const name = $("archiveName").value.trim();
   if (!name) return notice("Type the exact bucket name first.", true);
   try {
     await api("/api/buckets/archive", {method: "POST", body: JSON.stringify({name, confirmation: name})});
     $("archivePanel").hidden = true; notice("Archived “" + name + "” for 60 days."); refresh();
   } catch (error) { notice(error.message, true); }
 });
 $("cancelRestore").addEventListener("click", () => { $("restorePanel").hidden = true; });
 $("confirmRestore").addEventListener("click", async () => {
   const name = $("restoreName").value.trim();
   if (!name) return notice("Type the exact archived bucket name first.", true);
   try {
     await api("/api/buckets/restore", {method: "POST", body: JSON.stringify({name, confirmation: name})});
     $("restorePanel").hidden = true; notice("Restored “" + name + "”."); refresh();
   } catch (error) { notice(error.message, true); }
 });
 $("createBucket").addEventListener("click", async () => {
   const name = $("bucketName").value.trim();
   if (!name) return notice("Enter a bucket name.", true);
   try {
     const data = await api("/api/buckets", {method: "POST", body: JSON.stringify({name})});
     $("bucketName").value = "";
     const warnings = [data.panelReadAccess && data.panelReadAccess.warning, data.browserAccess && data.browserAccess.warning].filter(Boolean);
     notice(warnings.join(" ") || "Created bucket “" + name + "” with configured access.", Boolean(warnings.length));
     refresh();
   }
   catch (error) { notice(error.message, true); }
 });
 $("updateCloudflared").addEventListener("click", async () => {
   if (!confirm("Update Cloudflared and restart the Garage tunnel? Traffic may pause briefly.")) return;
   const button = $("updateCloudflared"); button.disabled = true;
   try {
     await api("/api/cloudflared/update", {method: "POST", body: JSON.stringify({confirmation: "update cloudflared"})});
     notice("Cloudflared updated and the tunnel was restarted."); refresh();
   } catch (error) { notice(error.message, true); refresh(); }
   finally { button.disabled = false; }
 });
 $("createKey").addEventListener("click", async () => {
   const name = $("keyName").value.trim();
   if (!name) return notice("Enter a key name.", true);
   try {
     const data = await api("/api/keys", {method: "POST", body: JSON.stringify({name})});
     $("keyName").value = "";
     const box = $("secretBox"); box.replaceChildren();
     const card = el("div", "secret");
     card.append(el("div", "", "Keep the secret safe — you can reveal it again after re-entering the panel password."));
     card.append(el("div", "", "Key ID:")); card.append(el("code", "", data.key.accessKeyId || ""));
     card.append(el("div", "", "Secret:")); card.append(el("code", "", data.key.secretAccessKey || ""));
     box.append(card);
     notice("Created key “" + name + "”."); refresh();
   } catch (error) { notice(error.message, true); }
 });
 $("revealKeys").addEventListener("click", () => {
   $("keyReveal").hidden = false;
   $("keyPassword").focus();
 });
$("hideKeys").addEventListener("click", () => {
  setKeysVisibility(false);
  notice("Secrets hidden again.");
});
$("cancelKeyDelete").addEventListener("click", () => {
   keyDeleteTarget = "";
   $("keyDeleteId").value = "";
   $("keyDeletePanel").hidden = true;
 });
 $("confirmKeyDelete").addEventListener("click", async () => {
   const id = $("keyDeleteId").value.trim();
   if (!keyDeleteTarget) return notice("Select a key from the revealed list first.", true);
   if (!id) return notice("Type the exact access key ID first.", true);
   if (id !== keyDeleteTarget) return notice("The access key ID does not match. Nothing was deleted.", true);
   if (!confirm("Delete access key “" + id + "”? This revokes it immediately.")) return;
   const button = $("confirmKeyDelete"); button.disabled = true;
   try {
     await api("/api/keys/delete", {method: "POST", body: JSON.stringify({id, confirmation: id})});
     $("keyDeletePanel").hidden = true;
     keyDeleteTarget = "";
     setKeysVisibility(false);
     notice("Deleted access key “" + id + "”.");
     refresh();
   } catch (error) { notice(error.message, true); }
   finally { button.disabled = false; }
 });
 $("confirmReveal").addEventListener("click", async () => {
   const password = $("keyPassword").value;
   if (!password) return notice("Enter the panel password to view keys.", true);
   try {
     const data = await api("/api/keys/reveal", {method: "POST", body: JSON.stringify({password})});
     $("keyPassword").value = "";
     $("keyReveal").hidden = true;
     // Merge revealed secrets into the cached metadata and re-render.
     accessKeyMetadata = data.keys || [];
     setKeysVisibility(true);
     notice("Secrets visible until you hide them or sign out.");
   } catch (error) { $("keyPassword").value = ""; notice(error.message, true); }
 });
 $("createApiKey").addEventListener("click", async () => {
   const name = $("apiKeyName").value.trim();
   if (!name) return notice("Enter a name for the key.", true);
   try {
     const data = await api("/api/apikeys", {method: "POST", body: JSON.stringify({name})});
     $("apiKeyName").value = "";
     const box = $("apiKeyBox"); box.replaceChildren();
     const card = el("div", "secret");
     card.append(el("div", "", "Copy this token now — it is stored hashed and cannot be shown again."));
     card.append(el("code", "", data.key.token));
     box.append(card);
     notice("Created API key “" + name + "”."); refresh();
   } catch (error) { notice(error.message, true); }
 });
 $("closeBrowser").addEventListener("click", closeBrowser);
 $("browserRefresh").addEventListener("click", () => { browserNextToken = ""; loadBrowser(); });
 $("browserUp").addEventListener("click", () => { browserPrefix = browserParent(browserPrefix); browserNextToken = ""; loadBrowser(); });
 $("browserNext").addEventListener("click", () => { if (browserNextToken) loadBrowser(browserNextToken); });
 $("browserUpload").addEventListener("change", event => {
   browserFile = event.target.files && event.target.files[0] ? event.target.files[0] : null;
   if (browserFile && browserMaxUploadBytes && browserFile.size > browserMaxUploadBytes) {
     setBrowserStatus("That file exceeds the " + bytes(browserMaxUploadBytes) + " upload limit.", "bad");
   }
   $("browserUploadButton").disabled = !browserCanWrite || !browserFile || (browserMaxUploadBytes && browserFile.size > browserMaxUploadBytes);
 });
 $("browserUploadButton").addEventListener("click", async () => {
   if (!browserCanWrite) return setBrowserStatus("File changes are not enabled for this panel.", "bad");
   if (!browserFile || !browserBucket) return setBrowserStatus("Choose a file first.", "bad");
   if (browserMaxUploadBytes && browserFile.size > browserMaxUploadBytes) return setBrowserStatus("That file is too large.", "bad");
   const file = browserFile, key = browserPrefix + file.name, button = $("browserUploadButton");
   button.disabled = true; setBrowserStatus("Uploading “" + key + "”…", "muted");
   try {
     const content = bytesToBase64(await file.arrayBuffer());
     await api("/api/bucket/upload", {method: "POST", body: JSON.stringify({bucket: browserBucket, key, content, contentType: file.type || "application/octet-stream"})});
     browserFile = null; $("browserUpload").value = "";
     notice("Uploaded “" + key + "”."); loadBrowser();
   } catch (error) { setBrowserStatus(error.message, "bad"); notice(error.message, true); button.disabled = false; }
 });
 $("grantBucket").addEventListener("change", () => {
   $("grant").disabled = !$("grantBucket").value || !$("grantKey").value;
   if (!$("grantBucket").value) setGrantStatus("Select a bucket, account, and permissions.", "muted");
 });
 $("grantKey").addEventListener("change", () => {
   $("grant").disabled = !$("grantBucket").value || !$("grantKey").value;
   if (!$("grantKey").value) setGrantStatus("Select a bucket, account, and permissions.", "muted");
 });
 $("grant").addEventListener("click", async () => {
   const bucketId = $("grantBucket").value, accessKeyId = $("grantKey").value;
   if (!bucketId || !accessKeyId) return setGrantStatus("Select a bucket and account first.", "bad");
   const button = $("grant");
   button.disabled = true;
   setGrantStatus("Applying access…", "muted");
   try {
     const data = await api("/api/grant", {method: "POST", body: JSON.stringify({bucketId, accessKeyId, read: $("permRead").checked, write: $("permWrite").checked, owner: $("permOwner").checked, allow: true})});
     const bucketName = $("grantBucket").selectedOptions[0].textContent.split(" · ")[0];
     const accountName = $("grantKey").selectedOptions[0].textContent.split(" · ")[0];
     const permissions = [data.permissions.read ? "read" : null, data.permissions.write ? "write" : null, data.permissions.owner ? "owner" : null].filter(Boolean).join(", ") || "no permissions";
     setGrantStatus("Granted " + permissions + " access to “" + accountName + "” on “" + bucketName + "”.", "ok");
     notice("Bucket access updated.");
     refresh();
   } catch (error) {
     setGrantStatus(error.message, "bad");
     notice(error.message, true);
   } finally { button.disabled = !$("grantBucket").value || !$("grantKey").value; }
 });
const VIEW_TITLES = {overview: "Overview", buckets: "Buckets", archived: "Archived buckets", keys: "Access keys", apikeys: "API keys", cluster: "Nodes & versions", logs: "Activity"};
function showView(name) {
  document.querySelectorAll(".view").forEach(view => view.classList.toggle("active", view.id === "view-" + name));
  document.querySelectorAll(".nav-btn").forEach(btn => btn.classList.toggle("active", btn.dataset.view === name));
  const title = $("viewTitle");
  if (title) title.textContent = VIEW_TITLES[name] || "Garage admin";
  if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
}
document.querySelectorAll(".nav-btn[data-view]").forEach(btn => {
  btn.addEventListener("click", () => showView(btn.dataset.view));
});
showView((location.hash || "#overview").slice(1));
refresh(); setInterval(refresh, 30000);
})();
</script></body></html>"""


def main() -> None:
    if not GARAGE_TOKEN:
        raise SystemExit("GARAGE_ADMIN_TOKEN is not set.")
    if not PANEL_PASSWORD:
        raise SystemExit("PANEL_PASSWORD is not set; refusing to serve without auth.")
    threading.Thread(
        target=archive_purge_loop,
        name="archived-bucket-purger",
        daemon=True,
    ).start()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"Garage panel listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
