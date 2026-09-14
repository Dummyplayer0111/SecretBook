"""Bounded early request inspection and explainable Django enforcement."""
from io import BytesIO
import logging
from pathlib import Path
import uuid

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from .detector import AttackDetector
from .preprocessing import canonicalize, MAX_TEXT_CHARS

logger = logging.getLogger(__name__)
SUPPORTED_BODY_TYPES = ("application/json", "application/x-www-form-urlencoded", "text/plain", "application/xml", "text/xml")


class InspectionError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def bounded_body(request, limit):
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except (ValueError, TypeError):
        raise InspectionError("Invalid Content-Length")
    if length < 0 or request.META.get("HTTP_TRANSFER_ENCODING"):
        raise InspectionError("Unsupported request framing")
    if length > limit:
        raise InspectionError("Request body exceeds inspection limit", 413)
    if hasattr(request, "_body"):
        body = request._body
    else:
        body = request.read(limit + 1)
        if len(body) <= limit:
            # Preserve the body for Django form parsing and downstream views.
            request._body = body
            request._stream = BytesIO(body)
    if len(body) > limit:
        raise InspectionError("Request body exceeds inspection limit", 413)
    return body


def request_text(request, max_body_bytes):
    if len(request.path) + len(request.META.get("QUERY_STRING", "")) > MAX_TEXT_CHARS * 6:
        raise InspectionError("Request URL exceeds inspection limit", 414)
    body = bounded_body(request, max_body_bytes)
    parts = [request.get_full_path()]
    content_type = request.content_type or ""
    if content_type in SUPPORTED_BODY_TYPES and body:
        parts.append(body.decode("utf-8", errors="replace"))
    elif content_type == "multipart/form-data" and body:
        # Only bounded multipart envelopes are parsed; file contents aren't scored.
        parts.append(request.POST.urlencode())
    elif body:
        raise InspectionError("Unsupported nonempty request body type", 415)
    normalized = canonicalize("\n".join(parts))
    if len(normalized) > MAX_TEXT_CHARS:
        raise InspectionError("Normalized request exceeds inspection limit", 413)
    return normalized


class AttackDetectionMiddleware:
    MODEL_DIR = Path(__file__).resolve().parent.parent.parent
    if not (MODEL_DIR / "attack_model.pt").is_file():
        MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
    detector_class = AttackDetector

    def __init__(self, get_response):
        self.get_response = get_response
        self.max_body_bytes = int(getattr(settings, "WAF_MAX_BODY_BYTES", 16_384))
        self.explain_blocks = bool(getattr(settings, "WAF_EXPLAIN_BLOCKS", True))
        threshold = getattr(settings, "WAF_ATTACK_THRESHOLD", None)
        self.detector = self.detector_class(
            self.MODEL_DIR / "attack_model.pt", self.MODEL_DIR / "char_dict.pkl", threshold=threshold)
        self.threshold = self.detector.threshold

    def __call__(self, request):
        try:
            inspected = request_text(request, self.max_body_bytes)
        except InspectionError as error:
            return JsonResponse({"detail": str(error), "request_id": uuid.uuid4().hex[:12]}, status=error.status)
        # Safe navigation is allowed only after a bounded read proves no body.
        if (request.method in ("GET", "HEAD") and not request.META.get("QUERY_STRING")
                and not request._body and request.path in getattr(settings, "WAF_SAFE_EMPTY_PATHS", ())):
            return self.get_response(request)
        result = self.detector.predict(inspected, explain=self.explain_blocks)
        request.attack_detection = result
        request.attack_score = result.score
        request.is_attack = result.is_attack
        request.inference_latency_ms = result.inference_latency_ms
        request_id = uuid.uuid4().hex[:12]
        # Never log request paths, payloads, or explanation text.
        logger.info("waf reference=%s method=%s attack=%s score=%.4f inference_ms=%.3f explanation_ms=%.3f",
                    request_id, request.method, result.is_attack, result.score,
                    result.inference_latency_ms, result.explanation_latency_ms)
        if result.is_attack:
            return self._blocked_response(request, result, request_id)
        response = self.get_response(request)
        if settings.DEBUG and getattr(settings, "WAF_EXPOSE_DEBUG_HEADERS", False):
            response["X-WAF-Score"] = f"{result.score:.4f}"
            response["X-WAF-Latency-Ms"] = f"{result.inference_latency_ms:.3f}"
        return response

    @staticmethod
    def _blocked_response(request, result, request_id):
        payload = {"detail": "Potential attack or anomalous request detected and blocked.",
                   "request_id": request_id, "attack_probability": round(result.score, 4),
                   "influential_spans": [vars(span) for span in result.influential_spans],
                   "explanation_method": "logit gradient-times-embedding",
                   "explanation_available": bool(result.influential_spans)}
        if request.content_type == "application/json" or "application/json" in request.headers.get("Accept", ""):
            return JsonResponse(payload, status=403)
        return render(request, "waf/blocked.html", payload, status=403)

