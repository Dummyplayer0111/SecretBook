"""Application-independent request representation; no route allowlist.

Passwords and valid CSRF tokens are deliberately outside classifier scope.
Only synthetic/redacted representations should be written to research artifacts.
"""
import json
import re
from urllib.parse import parse_qsl, urlsplit
from .preprocessing import canonicalize, MAX_TEXT_CHARS

REPRESENTATION_VERSION = "field-aware-route-shape-v2"
PASSWORD_FIELDS = frozenset({"password", "password1", "password2", "old_password",
                             "new_password", "new_password1", "new_password2",
                             "password_confirmation", "confirm_password"})
CSRF_FIELDS = frozenset({"csrfmiddlewaretoken", "csrf_token", "_csrf", "_token"})
IDENTIFIER = re.compile(r"[\w.@~-]+\Z", re.UNICODE)
TOKEN = re.compile(r"(?:[a-zA-Z0-9]{32}|[a-zA-Z0-9]{64})\Z")


def field_parts(pairs, kind):
    result = []
    for key, value in pairs:
        key, value = str(key), str(value)
        normalized_key = canonicalize(key)
        if normalized_key in PASSWORD_FIELDS:
            continue
        if normalized_key in CSRF_FIELDS and TOKEN.fullmatch(value):
            continue
        # Ordinary field names are metadata. Preserve suspicious keys as payload.
        if not IDENTIFIER.fullmatch(normalized_key):
            result.append(kind + " key " + canonicalize(key))
        result.append(kind + " value " + canonicalize(value))
    return result


def json_pairs(value, key="value", depth=0):
    if depth > 32:
        raise ValueError("JSON nesting exceeds inspection limit")
    if isinstance(value, dict):
        for name, item in value.items():
            if canonicalize(str(name)) in PASSWORD_FIELDS:
                continue
            yield from json_pairs(item, str(name), depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from json_pairs(item, key, depth + 1)
    else:
        yield key, str(value) if value is not None else "null"


def represent(method, target, body="", content_type="", form_pairs=None):
    """Return a bounded normalized string shared by fitting and Django runtime."""
    parsed = urlsplit(target)
    path = canonicalize(parsed.path or "/")
    # Route shape generalizes ordinary endpoint names, retaining unusual content.
    path_parts = ["<route>" if IDENTIFIER.fullmatch(part) else part
                  for part in path.split("/") if part]
    chunks = ["method " + method.lower(), "path /" + "/".join(path_parts)]
    chunks.extend(field_parts(parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=512), "query"))
    content_type = content_type.split(";", 1)[0].strip().lower()
    if form_pairs is not None:
        chunks.extend(field_parts(form_pairs, "form"))
    elif body and content_type == "application/x-www-form-urlencoded":
        chunks.extend(field_parts(parse_qsl(body, keep_blank_values=True, max_num_fields=512), "form"))
    elif body and content_type == "application/json":
        try:
            value = json.loads(body)
        except (ValueError, RecursionError):
            # Fail explicitly rather than leak malformed credential bodies to XAI.
            raise ValueError("Malformed JSON request")
        chunks.extend(field_parts(json_pairs(value), "json"))
    elif body:
        chunks.append("body " + canonicalize(body))
    text = "\n".join(chunks)
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError("Represented request exceeds inspection limit")
    return text
