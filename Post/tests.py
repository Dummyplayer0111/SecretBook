import json
from pathlib import Path
from unittest.mock import patch
import numpy as np
import torch
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from .detector import AttackCNN, AttackDetector, DetectionResult, ExplanationSpan
from .middleware import AttackDetectionMiddleware, InspectionError, request_text
from .preprocessing import canonicalize, text_windows, MAX_LEN, MAX_TEXT_CHARS
from .models import Post


class FakeDetector:
    def __init__(self, result):
        self.result, self.seen = result, None

    def predict(self, text, explain=True):
        self.seen = text
        return self.result


class PreprocessingTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_nested_decoding_and_nul(self):
        self.assertEqual(canonicalize("%2527%20OR%20&#49;=1"), "' or 1=1")
        self.assertEqual(canonicalize("%00"), r"\x00")

    def test_multipart_text_and_downstream_body_preserved(self):
        request = self.factory.post("/login/?next=%2F", {"username": "admin' OR 1=1--"})
        original = request.body
        self.assertIn("username=admin' or 1=1--", request_text(request, 16384))
        self.assertEqual(request.body, original)
        self.assertEqual(request.POST["username"], "admin' OR 1=1--")

    def test_urlencoded_body(self):
        request = self.factory.post("/login/", "username=admin%27+OR+1%3D1--", content_type="application/x-www-form-urlencoded")
        self.assertIn("username=admin' or 1=1--", request_text(request, 16384))
        self.assertEqual(request.POST["username"], "admin' OR 1=1--")

    def test_json_body(self):
        request = self.factory.post("/api", '{"text":"<script>alert(1)</script>"}', content_type="application/json")
        self.assertIn("<script>", request_text(request, 16384))

    def test_large_declared_body_rejected_without_read(self):
        request = self.factory.post("/api", "x" * 100, content_type="text/plain")
        with patch.object(request, "read") as read:
            with self.assertRaises(InspectionError) as error:
                request_text(request, 10)
            self.assertEqual(error.exception.status, 413)
            read.assert_not_called()

    def test_missing_length_still_bounded(self):
        request = self.factory.post("/api", "x" * 100, content_type="text/plain")
        request.META.pop("CONTENT_LENGTH")
        with patch.object(request, "read", wraps=request.read) as read:
            with self.assertRaises(InspectionError):
                request_text(request, 10)
            read.assert_called_once_with(11)

    def test_invalid_length_and_oversized_url(self):
        request = self.factory.get("/api")
        request.META["CONTENT_LENGTH"] = "bad"
        with self.assertRaises(InspectionError) as error:
            request_text(request, 16384)
        self.assertEqual(error.exception.status, 400)
        request = self.factory.get("/api", {"q": "x" * (MAX_TEXT_CHARS * 7)})
        with self.assertRaises(InspectionError) as error:
            request_text(request, 16384)
        self.assertEqual(error.exception.status, 414)

    def test_window_coverage_including_old_blind_spot(self):
        text = "<script>alert(1)</script>" + "x" * 2000
        covered = np.zeros(len(text), dtype=bool)
        for offset, window in text_windows(text):
            covered[offset:offset+len(window)] = True
            self.assertLessEqual(len(window), MAX_LEN)
        self.assertTrue(covered.all())
        self.assertTrue(text_windows(text)[0][1].startswith("<script>"))
        with self.assertRaises(ValueError):
            text_windows("x" * (MAX_TEXT_CHARS + 1))


@override_settings(DEBUG=False)
class MiddlewareTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def middleware(self, attack=False):
        result = DetectionResult(.99 if attack else .1, attack, .2, .8, "/api",
                                 (ExplanationSpan("or 1=1", 0, 6, .9),) if attack else ())
        middleware = AttackDetectionMiddleware.__new__(AttackDetectionMiddleware)
        middleware.get_response = lambda request: HttpResponse("allowed")
        middleware.max_body_bytes, middleware.explain_blocks = 16384, True
        middleware.detector = FakeDetector(result)
        return middleware

    def test_benign_scored_before_forwarding(self):
        middleware = self.middleware()
        request = self.factory.get("/api", {"q": "books"})
        self.assertEqual(middleware(request).status_code, 200)
        self.assertIsNotNone(middleware.detector.seen)
        self.assertFalse(request.is_attack)

    def test_empty_navigation_bypass_but_get_head_bodies_inspected(self):
        for method in ("GET", "HEAD"):
            empty = self.middleware()
            self.assertEqual(empty(self.factory.generic(method, "/feed/")).status_code, 200)
            self.assertIsNone(empty.detector.seen)
            with_body = self.middleware(True)
            request = self.factory.generic(method, "/feed/", "<script>alert(1)</script>", content_type="text/plain")
            self.assertEqual(with_body(request).status_code, 403)
            self.assertIn("<script>", with_body.detector.seen)

    def test_html_and_json_block(self):
        response = self.middleware(True)(self.factory.get("/api?q=attack"))
        self.assertContains(response, "or 1=1", status_code=403)
        response = self.middleware(True)(self.factory.get("/api?q=attack", HTTP_ACCEPT="application/json"))
        payload = json.loads(response.content)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(payload["explanation_available"])
        self.assertEqual(payload["attack_probability"], .99)

    def test_logging_contains_no_payload_or_spans(self):
        with self.assertLogs("Post.middleware", level="INFO") as logs:
            self.middleware(True)(self.factory.get("/private-secret?q=attack"))
        output = " ".join(logs.output)
        self.assertNotIn("private-secret", output)
        self.assertNotIn("or 1=1", output)

    def test_invalid_framing_is_400_and_unsupported_body_is_415(self):
        request = self.factory.get("/api")
        request.META["CONTENT_LENGTH"] = "-1"
        self.assertEqual(self.middleware()(request).status_code, 400)
        request = self.factory.post("/api", b"binary", content_type="application/octet-stream")
        self.assertEqual(self.middleware()(request).status_code, 415)


class ExplanationTests(SimpleTestCase):
    def test_logit_saliency_survives_sigmoid_saturation(self):
        torch.manual_seed(7)
        detector = AttackDetector.__new__(AttackDetector)
        detector.char2idx = {c: i + 2 for i, c in enumerate(sorted(set("<script>alert(1)</script>")))}
        detector.model = AttackCNN(max(detector.char2idx.values()) + 1).eval()
        with torch.no_grad():
            detector.model.fc2.bias.fill_(100)
        detector.threshold = .5
        result = detector.predict("<script>alert(1)</script>")
        self.assertEqual(result.score, 1)
        self.assertTrue(result.influential_spans)
        self.assertTrue(all(parameter.grad is None for parameter in detector.model.parameters()))


VIEW_MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]


@override_settings(MIDDLEWARE=VIEW_MIDDLEWARE)
class PostViewTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner", password="test-pass")
        self.other = User.objects.create_user("other", password="test-pass")
        self.post = Post.objects.create(author=self.owner, title="Original", text="Text")
        self.client.force_login(self.owner)

    def test_invalid_create_and_edit_render_errors(self):
        self.assertEqual(self.client.post(reverse("post_new"), {}).status_code, 200)
        self.assertEqual(self.client.post(reverse("post_edit", args=[self.post.pk]), {}).status_code, 200)
        self.assertEqual(Post.objects.count(), 1)

    def test_edit_preserves_creation_time(self):
        created = self.post.created_date
        self.assertEqual(self.client.post(reverse("post_edit", args=[self.post.pk]), {"title": "Updated", "text": "Body"}).status_code, 302)
        self.post.refresh_from_db()
        self.assertEqual(self.post.created_date, created)

    def test_get_cannot_delete_and_owner_post_can(self):
        url = reverse("delete", args=[self.post.pk])
        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertTrue(Post.objects.filter(pk=self.post.pk).exists())
        self.assertEqual(self.client.post(url).status_code, 200)
        self.assertFalse(Post.objects.filter(pk=self.post.pk).exists())

    def test_unauthorized_edit_and_delete_are_404(self):
        self.client.force_login(self.other)
        self.assertEqual(self.client.get(reverse("post_edit", args=[self.post.pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse("delete", args=[self.post.pk])).status_code, 404)
        self.assertTrue(Post.objects.filter(pk=self.post.pk).exists())

    def test_anonymous_delete_redirects_to_login(self):
        self.client.logout()
        self.assertEqual(self.client.post(reverse("delete", args=[self.post.pk])).status_code, 302)


class RealModelIntegrationTests(SimpleTestCase):
    def test_saved_model_through_real_middleware_json_body(self):
        request = RequestFactory().post("/api", '{"q":"<script>alert(1)</script>"}', content_type="application/json")
        middleware = AttackDetectionMiddleware(lambda request: HttpResponse("allowed"))
        response = middleware(request)
        self.assertTrue(hasattr(request, "attack_detection"))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(json.loads(response.content)["explanation_available"])
