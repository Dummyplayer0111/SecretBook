import json
from pathlib import Path
from unittest.mock import patch
import numpy as np
import torch
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.test import Client, RequestFactory, SimpleTestCase, TestCase, override_settings
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

    def test_csrf_metadata_excluded_without_changing_form_or_body(self):
        from urllib.parse import urlencode
        for length in (32, 64):
            fields = {"csrfmiddlewaretoken": "A" * length,
                      "username": "admin' OR 1=1--", "password": "synthetic"}
            requests = [self.factory.post("/login/", fields),
                        self.factory.post("/login/", urlencode(fields),
                                          content_type="application/x-www-form-urlencoded")]
            for request in requests:
                original = request.body
                text = request_text(request, 16384)
                self.assertNotIn("csrfmiddlewaretoken", text)
                self.assertIn("username=admin' or 1=1--", text)
                self.assertEqual(request.POST["csrfmiddlewaretoken"], "A" * length)
                self.assertEqual(request.body, original)

    def test_malformed_and_duplicate_csrf_fields_remain_inspected(self):
        for body in ("csrfmiddlewaretoken=%3Cscript%3Ealert(1)%3C/script%3E",
                     "csrfmiddlewaretoken=" + "A" * 32 + "&csrfmiddlewaretoken=" + "B" * 32):
            request = self.factory.post("/login/", body,
                                        content_type="application/x-www-form-urlencoded")
            self.assertIn("csrfmiddlewaretoken=", request_text(request, 16384))

    def test_login_credentials_are_preserved_but_not_scored(self):
        fields = {"username": "24bce0000", "password": "Private'<script>Example",
                  "next": "/feed/", "comment": "<script>alert(1)</script>"}
        request = self.factory.post("/login/?next=/feed/", fields)
        original = request.body
        text = request_text(request, 16384)
        self.assertNotIn("24bce0000", text)
        self.assertNotIn("password", text)
        self.assertNotIn("private", text)
        self.assertIn("comment=<script>alert(1)</script>", text)
        self.assertEqual(request.POST.dict(), fields)
        self.assertEqual(request.body, original)
        other = request_text(self.factory.post("/api", fields), 16384)
        self.assertIn("username=24bce0000", other)

    def test_login_duplicate_or_nonstandard_usernames_remain_scored(self):
        for usernames in (["alice", "bob"], ["admin' OR 1=1--"]):
            text = request_text(self.factory.post("/login/", {"username": usernames}), 16384)
            self.assertIn("username=", text)

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


@override_settings(DEBUG=False, WAF_PIPELINE="legacy", WAF_MODE="block")
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

    def test_login_navigation_and_known_redirects_bypass(self):
        for path in ("/login", "/login/", "/login/?next=/feed/",
                     "/login/?next=%2Fuser_list%2F", "/login/?next=/"):
            middleware = self.middleware(True)
            self.assertEqual(middleware(self.factory.get(path)).status_code, 200)
            self.assertIsNone(middleware.detector.seen)

    def test_login_exemption_does_not_cover_other_inputs(self):
        for path in ("/login/?next=https://example.com/", "/login/?next=//example.com/",
                     "/login/?next=/feed/&next=/", "/login/?next=/feed/&q=attack",
                     "/login/?next=/feed/%3Fq=attack", "/login/?q=attack"):
            middleware = self.middleware(True)
            self.assertEqual(middleware(self.factory.get(path)).status_code, 403)
            self.assertIsNotNone(middleware.detector.seen)
        for method in ("GET", "HEAD", "POST"):
            middleware = self.middleware(True)
            request = self.factory.generic(method, "/login/?next=/feed/", "attack",
                                           content_type="text/plain")
            self.assertEqual(middleware(request).status_code, 403)

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


@override_settings(WAF_PIPELINE="legacy", WAF_MODE="block")
class RealModelIntegrationTests(SimpleTestCase):
    def test_saved_model_through_real_middleware_json_body(self):
        request = RequestFactory().post("/api", '{"q":"<script>alert(1)</script>"}', content_type="application/json")
        middleware = AttackDetectionMiddleware(lambda request: HttpResponse("allowed"))
        response = middleware(request)
        self.assertTrue(hasattr(request, "attack_detection"))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(json.loads(response.content)["explanation_available"])


@override_settings(WAF_PIPELINE="legacy", WAF_MODE="block")
class LoginFlowIntegrationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.password = "Synthetic!'<script> OR 1=1--"
        cls.user = User.objects.create_user("24bce0000", password=cls.password)

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.client.get("/login/")
        self.token = self.client.cookies["csrftoken"].value

    def test_real_login_with_student_style_username_and_opaque_password(self):
        from urllib.parse import urlencode
        response = self.client.post("/login/?next=/feed/", urlencode({
            "username": self.user.username, "password": self.password,
            "csrfmiddlewaretoken": self.token}), content_type="application/x-www-form-urlencoded")
        self.assertRedirects(response, "/feed/", fetch_redirect_response=False)
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))

    def test_login_still_requires_csrf_and_correct_password(self):
        response = self.client.post("/login/", {
            "username": self.user.username, "password": self.password})
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/login/", {
            "username": self.user.username, "password": "wrong",
            "csrfmiddlewaretoken": self.token})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_sql_injection_username_block_does_not_expose_password(self):
        response = self.client.post("/login/", {
            "username": "admin' OR 1=1--", "password": self.password,
            "csrfmiddlewaretoken": self.token}, HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 403)
        payload = response.json()
        self.assertIn("attack_probability", payload)
        self.assertNotIn("synthetic", response.content.decode().lower())

    def test_account_page_navigation_and_authentication_requirement(self):
        response = self.client.get("/password_change/")
        self.assertRedirects(response, "/login/?next=/password_change/", fetch_redirect_response=False)
        self.assertEqual(self.client.get(response.url).status_code, 200)
        self.client.force_login(self.user)
        for path in ("/password_change/", "/password_change/done/", "/password_reset/",
                     "/password_reset/done/", "/reset/done/"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_password_change_validates_csrf_old_password_and_updates_password(self):
        self.client.force_login(self.user)
        new_password = "Replacement!'<script> OR 1=1--"
        fields = {"old_password": self.password, "new_password1": new_password,
                  "new_password2": new_password}
        self.assertEqual(self.client.post("/password_change/", fields).status_code, 403)
        fields["csrfmiddlewaretoken"] = self.token
        fields["old_password"] = "incorrect"
        response = self.client.post("/password_change/", fields)
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))
        fields["old_password"] = self.password
        response = self.client.post("/password_change/", fields)
        self.assertRedirects(response, "/password_change/done/", fetch_redirect_response=False)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

    def test_reset_confirmation_token_validation_and_password_submission(self):
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        self.assertEqual(self.client.get(f"/reset/{uid}/invalid-token/").status_code, 200)
        response = self.client.get(f"/reset/{uid}/{token}/")
        self.assertEqual(response.status_code, 302)
        reset_path = response.url
        self.assertEqual(self.client.get(reset_path).status_code, 200)
        new_password = "Reset!'<script> OR 1=1--"
        response = self.client.post(reset_path, {"new_password1": new_password,
            "new_password2": new_password, "csrfmiddlewaretoken": self.token})
        self.assertRedirects(response, "/reset/done/", fetch_redirect_response=False)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

    def test_password_change_extra_payload_still_scored_without_passwords(self):
        request = RequestFactory().post("/password_change/", {
            "old_password": "PrivateOld", "new_password1": "PrivateNew",
            "new_password2": "PrivateNew", "extra": "<script>alert(1)</script>"})
        text = request_text(request, 16384)
        self.assertNotIn("private", text)
        self.assertIn("<script>", text)
        self.assertFalse(request._waf_auth_metadata_only)
        middleware = AttackDetectionMiddleware(lambda request: HttpResponse("allowed"))
        self.assertEqual(middleware(request).status_code, 403)
