"""Shared, versioned preprocessing for dataset construction and live requests."""
import html
import re
import unicodedata
from urllib.parse import unquote_plus

PREPROCESSING_VERSION = "nfkc-html-url2-windows-v1"
MAX_LEN = 256
WINDOW_STRIDE = 192
MAX_TEXT_CHARS = 4096


def canonicalize(value: str, decoding_passes: int = 2) -> str:
    value = unicodedata.normalize("NFKC", value)
    for _ in range(decoding_passes):
        decoded = unquote_plus(html.unescape(value))
        if decoded == value:
            break
        value = decoded
    value = value.replace("\x00", r"\x00")
    return re.sub(r"\s+", " ", value).strip().lower()


def text_windows(text: str):
    """Cover every character with overlapping windows; never silently truncate."""
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError("Normalized request exceeds inspection limit")
    if len(text) <= MAX_LEN:
        return [(0, text)]
    starts = list(range(0, len(text) - MAX_LEN + 1, WINDOW_STRIDE))
    if starts[-1] + MAX_LEN < len(text):
        starts.append(len(text) - MAX_LEN)
    return [(start, text[start:start + MAX_LEN]) for start in starts]
