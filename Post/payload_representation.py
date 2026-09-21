"""Version-three component extraction, independent of application route names."""
import json
from urllib.parse import parse_qsl, urlsplit
from .preprocessing import canonicalize, MAX_TEXT_CHARS
from .representation import PASSWORD_FIELDS, CSRF_FIELDS, IDENTIFIER, TOKEN

REPRESENTATION_VERSION = "request-components-relative-url-v3"
PREFIX = "/search?q="
SEPARATOR = "\n<component>\n"


def components(method, target, body="", content_type="", form_pairs=None):
    values = []

    def add(value, depth=0):
        if depth > 8:
            raise ValueError("Nested URL exceeds inspection limit")
        value = canonicalize(str(value))
        if value.startswith("/"):
            relative = urlsplit(value)
            parts = [p for p in relative.path.split("/") if p]
            if all(IDENTIFIER.fullmatch(part) for part in parts):
                values.append(PREFIX + "<relative-url>")
                for key, child in parse_qsl(relative.query, keep_blank_values=True, max_num_fields=512):
                    field(key, child, depth + 1)
                if relative.fragment:
                    add(relative.fragment, depth + 1)
                return
        values.append(PREFIX + value)

    def field(key, value, depth=0):
        key = canonicalize(str(key))
        if key in PASSWORD_FIELDS:
            return
        if key in CSRF_FIELDS and TOKEN.fullmatch(str(value)):
            return
        if not IDENTIFIER.fullmatch(key):
            add(key, depth)
        add(value, depth)

    def walk(item, key="value", depth=0):
        if depth > 32:
            raise ValueError("JSON nesting exceeds inspection limit")
        if canonicalize(str(key)) in PASSWORD_FIELDS:
            return
        if isinstance(item, dict):
            if not IDENTIFIER.fullmatch(canonicalize(str(key))):
                add(key)
            for child_key, child in item.items():
                walk(child, child_key, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, key, depth + 1)
        else:
            field(key, "null" if item is None else str(item))

    parsed = urlsplit(target)
    path = canonicalize(parsed.path or "/")
    if any(not IDENTIFIER.fullmatch(part) for part in path.split("/") if part):
        add(path)
    for key, value in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=512):
        field(key, value)
    content_type = content_type.split(";", 1)[0].strip().lower()
    if form_pairs is not None:
        for key, value in form_pairs:
            field(key, value)
    elif body and content_type == "application/x-www-form-urlencoded":
        for key, value in parse_qsl(body, keep_blank_values=True, max_num_fields=512):
            field(key, value)
    elif body and content_type == "application/json":
        try:
            item = json.loads(body)
        except (ValueError, RecursionError):
            raise ValueError("Malformed JSON request")
        walk(item)
    elif body:
        add(body)
    if not values:
        values = [PREFIX + "<empty>"]
    # Every component participates in request scoring; never truncate silently.
    if len(values) > 128 or len(SEPARATOR.join(values)) > MAX_TEXT_CHARS:
        raise ValueError("Represented request exceeds inspection limit")
    return values


def represent(method, target, body="", content_type="", form_pairs=None):
    return SEPARATOR.join(components(method, target, body, content_type, form_pairs))
