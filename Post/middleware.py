"""Bounded early request inspection and explainable Django enforcement."""
from io import BytesIO
import logging
import re
from pathlib import Path
import uuid

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.urls import resolve, Resolver404
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
    request._waf_auth_metadata_only = False
    if len(request.path) + len(request.META.get("QUERY_STRING", "")) > MAX_TEXT_CHARS * 6:
        raise InspectionError("Request URL exceeds inspection limit", 414)
    body = bounded_body(request, max_body_bytes)
    parts = [request.get_full_path()]
    content_type = request.content_type or ""
    if content_type in ("application/x-www-form-urlencoded", "multipart/form-data") and body:
        # Work on a copy: Django still receives and validates the original token.
        # Random framework tokens aren't application payload. Malformed or
        # repeated token fields remain visible to the detector.
        fields = request.POST.copy()
        tokens = fields.getlist("csrfmiddlewaretoken")
        if len(tokens) == 1 and re.fullmatch(r"(?:[A-Za-z0-9]{32}|[A-Za-z0-9]{64})", tokens[0]):
            del fields["csrfmiddlewaretoken"]
        from django.contrib.auth.views import LoginView, PasswordChangeView, PasswordResetConfirmView, LogoutView
        view_class = standard_view_class(request)
        password_fields = {
            LoginView: ("password",),
            PasswordChangeView: ("old_password", "new_password1", "new_password2"),
            PasswordResetConfirmView: ("new_password1", "new_password2"),
            LogoutView: (),
        }
        if view_class in password_fields:
            # Passwords are opaque secrets, not classifier input. Django's
            # authentication backend receives the unchanged original values.
            for field in password_fields[view_class]:
                fields.pop(field, None)
        if view_class is LoginView:
            usernames = fields.getlist("username")
            if len(usernames) == 1 and re.fullmatch(r"[\w.@+-]{1,150}", usernames[0]):
                del fields["username"]
            safe_paths = getattr(settings, "WAF_SAFE_EMPTY_PATHS", ())
            if len(fields.getlist("next")) == 1 and fields["next"] in safe_paths:
                del fields["next"]
            if (set(request.GET) == {"next"} and len(request.GET.getlist("next")) == 1
                    and request.GET["next"] in safe_paths):
                parts[0] = request.path
        if view_class in password_fields:
            request._waf_auth_metadata_only = (
                request.method == "POST" and not fields and parts[0] == request.path)
        parts.append(fields.urlencode())
    elif content_type in SUPPORTED_BODY_TYPES and body:
        parts.append(body.decode("utf-8", errors="replace"))
    elif body:
        raise InspectionError("Unsupported nonempty request body type", 415)
    normalized = canonicalize("\n".join(parts))
    if len(normalized) > MAX_TEXT_CHARS:
        raise InspectionError("Normalized request exceeds inspection limit", 413)
    return normalized


def standard_view_class(request):
    # Bind credential handling to Django's actual view, not a path substring.
    try:
        match = resolve(request.path_info)
    except Resolver404:
        return None
    return getattr(match.func, "view_class", None)


def structured_request_text(request, max_body_bytes, component_mode=False):
    if component_mode:
        from .payload_representation import represent
    else:
        from .representation import represent
    if len(request.path) + len(request.META.get("QUERY_STRING", "")) > MAX_TEXT_CHARS * 6:
        raise InspectionError("Request URL exceeds inspection limit", 414)
    body = bounded_body(request, max_body_bytes)
    content_type = request.content_type or ""
    pairs = None
    if body and content_type == "multipart/form-data":
        if request.method != "POST":
            raise InspectionError("Multipart inspection supports POST only", 415)
        pairs = [(key, value) for key, values in request.POST.lists() for value in values]
    elif body and content_type not in SUPPORTED_BODY_TYPES:
        raise InspectionError("Unsupported nonempty request body type", 415)
    try:
        return represent(request.method, request.get_full_path(), body.decode("utf-8", errors="replace"),
                         content_type, form_pairs=pairs)
    except ValueError as error:
        raise InspectionError(str(error), 413 if "limit" in str(error) else 400)


class AttackDetectionMiddleware:
    MODEL_DIR = Path(__file__).resolve().parent.parent.parent
    if not (MODEL_DIR / "attack_model.pt").is_file():
        MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
    detector_class = AttackDetector

    def __init__(self, get_response):
        self.get_response = get_response
        self.max_body_bytes = int(getattr(settings, "WAF_MAX_BODY_BYTES", 16_384))
        self.explain_blocks = bool(getattr(settings, "WAF_EXPLAIN_BLOCKS", True))
        self.pipeline = getattr(settings, "WAF_PIPELINE", "legacy")
        self.mode = getattr(settings, "WAF_MODE", "block")
        if self.mode not in ("monitor", "block"):
            raise ValueError("WAF_MODE must be monitor or block")
        if self.pipeline in ("structured", "components"):
            from .structured_detector import load_candidate
            from .representation import REPRESENTATION_VERSION as FIELD_VERSION
            from .payload_representation import REPRESENTATION_VERSION as COMPONENT_VERSION
            self.detector = load_candidate(settings.WAF_CANDIDATE_DIR,
                                          getattr(settings, "WAF_CANDIDATE_THRESHOLD", None),
                                          expected_version=COMPONENT_VERSION if self.pipeline == "components" else FIELD_VERSION)
        elif self.pipeline == "legacy":
            threshold = getattr(settings, "WAF_ATTACK_THRESHOLD", None)
            self.detector = self.detector_class(
                self.MODEL_DIR / "attack_model.pt", self.MODEL_DIR / "char_dict.pkl", threshold=threshold)
        else:
            raise ValueError("Unknown WAF pipeline")
        self.threshold = self.detector.threshold

    def __call__(self, request):
        try:
            structured = getattr(self, "pipeline", "legacy") in ("structured", "components")
            inspected = (structured_request_text(request, self.max_body_bytes, self.pipeline == "components")
                         if structured else request_text(request, self.max_body_bytes))
        except InspectionError as error:
            return JsonResponse({"detail": str(error), "request_id": uuid.uuid4().hex[:12]}, status=error.status)
        # Safe navigation is allowed only after a bounded read proves no body.
        if not structured and (self._safe_navigation(request) or request._waf_auth_metadata_only):
            return self.get_response(request)
        result = self.detector.predict(inspected, explain=self.explain_blocks)
        request.attack_detection = result
        request.attack_score = result.score
        request.is_attack = result.is_attack
        request.inference_latency_ms = result.inference_latency_ms
        request.waf_mode = getattr(self, "mode", "block")
        request_id = uuid.uuid4().hex[:12]
        # Never log request paths, payloads, or explanation text.
        logger.info("waf reference=%s method=%s mode=%s attack=%s score=%.4f inference_ms=%.3f explanation_ms=%.3f",
                    request_id, request.method, request.waf_mode, result.is_attack, result.score,
                    result.inference_latency_ms, result.explanation_latency_ms)
        if result.is_attack and getattr(self, "mode", "block") == "block":
            return self._blocked_response(request, result, request_id)
        response = self.get_response(request)
        if settings.DEBUG and getattr(settings, "WAF_EXPOSE_DEBUG_HEADERS", False):
            response["X-WAF-Score"] = f"{result.score:.4f}"
            response["X-WAF-Latency-Ms"] = f"{result.inference_latency_ms:.3f}"
        return response

    @staticmethod
    def _safe_navigation(request):
        if request.method not in ("GET", "HEAD") or request._body:
            return False
        safe_paths = getattr(settings, "WAF_SAFE_EMPTY_PATHS", ())
        from django.contrib.auth.views import PasswordResetConfirmView
        if (not request.META.get("QUERY_STRING")
                and standard_view_class(request) is PasswordResetConfirmView):
            return True
        # CommonMiddleware adds the trailing slash after this middleware runs.
        path = request.path if request.path.endswith("/") else request.path + "/"
        if path not in safe_paths:
            return False
        if not request.META.get("QUERY_STRING"):
            return True
        # Django's authentication redirects carry a next parameter. Only exact
        # known navigation destinations qualify; arbitrary queries remain scored.
        return (path == "/login/" and set(request.GET) == {"next"}
                and len(request.GET.getlist("next")) == 1
                and request.GET["next"] in safe_paths)

    @staticmethod
    def _blocked_response(request, result, request_id):
        payload = {"detail": "Potential attack or anomalous request detected and blocked.",
                   "request_id": request_id, "attack_probability": round(result.score, 4),
                   "influential_spans": [vars(span) for span in result.influential_spans],
                   "explanation_method": "model sensitivity attribution",
                   "explanation_available": bool(result.influential_spans)}
        if request.content_type == "application/json" or "application/json" in request.headers.get("Accept", ""):
            return JsonResponse(payload, status=403)
        return render(request, "waf/blocked.html", payload, status=403)

