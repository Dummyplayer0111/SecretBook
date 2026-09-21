from urllib.parse import urlencode
from pathlib import Path
from unittest.mock import patch
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, TestCase, Client, override_settings
from .detector import DetectionResult
from .middleware import AttackDetectionMiddleware, structured_request_text, InspectionError
from .representation import represent


class RepresentationTests(SimpleTestCase):
    def test_route_names_and_credentials_do_not_drive_score(self):
        first = represent("POST", "/account/password_change/", urlencode({"old_password": "secret123", "new_password1": "<script>private"}), "application/x-www-form-urlencoded")
        second = represent("POST", "/members/reset/", urlencode({"old_password": "entirely different", "new_password1": "abc"}), "application/x-www-form-urlencoded")
        self.assertEqual(first, second)
        self.assertNotIn("secret", first)
        self.assertNotIn("script", first)

    def test_username_queries_keys_and_unusual_paths_remain_visible(self):
        text = represent("POST", "/%3Cscript%3E/?" + urlencode({"q": "' OR 1=1--"}),
                         urlencode({"username": "24bce0000", "<script>": "value"}), "application/x-www-form-urlencoded")
        self.assertIn("24bce0000", text)
        self.assertIn("' or 1=1--", text)
        self.assertIn("<script>", text)

    def test_json_nested_credentials_removed_and_other_values_kept(self):
        text = represent("POST", "/any/", '{"user":{"password":"private","text":"<script>alert(1)</script>"}}', "application/json")
        self.assertNotIn("private", text)
        self.assertIn("<script>", text)

    def test_csrf_and_duplicate_payload_values(self):
        text = represent("POST", "/any/", urlencode([("csrfmiddlewaretoken", "A"*64), ("q", "normal"), ("q", "<script>")]), "application/x-www-form-urlencoded")
        self.assertNotIn("a"*64, text)
        self.assertIn("normal", text)
        self.assertIn("<script>", text)

    def test_runtime_and_training_representation_match_preserving_original(self):
        fields = {"username": "24bce0000", "password": "PrivateExample", "text": "O'Reilly"}
        encoded = urlencode(fields)
        expected = represent("POST", "/brand_new/login/?next=/welcome/", encoded, "application/x-www-form-urlencoded")
        factory = RequestFactory()
        for request in (factory.post("/brand_new/login/?next=/welcome/", fields),
                        factory.post("/brand_new/login/?next=/welcome/", encoded, content_type="application/x-www-form-urlencoded")):
            body = request.body
            self.assertEqual(structured_request_text(request, 16384), expected)
            self.assertEqual(request.body, body)
            self.assertEqual(request.POST["password"], fields["password"])

    def test_bad_json_and_large_secret_are_explicitly_rejected(self):
        with self.assertRaises(InspectionError):
            structured_request_text(RequestFactory().post("/any/", '{"password":', content_type="application/json"), 16384)
        with self.assertRaises(InspectionError):
            structured_request_text(RequestFactory().post("/any/", {"password": "x"*20000}), 16384)

    def test_urlencoded_bodies_are_inspected_for_every_method(self):
        body = urlencode({"q": "<script>alert(1)</script>", "password": "PrivateExample"})
        for method in ("GET", "HEAD", "POST", "PUT", "PATCH"):
            request = RequestFactory().generic(method, "/api/", body, content_type="application/x-www-form-urlencoded")
            text = structured_request_text(request, 16384)
            self.assertEqual(text, represent(method, "/api/", body, "application/x-www-form-urlencoded"))
            self.assertIn("<script>", text)
            self.assertNotIn("privateexample", text)

    def test_non_post_multipart_is_explicitly_out_of_scope(self):
        request = RequestFactory().generic("PUT", "/api/", b"multipart-data", content_type="multipart/form-data; boundary=test")
        with self.assertRaises(InspectionError) as caught:
            structured_request_text(request, 16384)
        self.assertEqual(caught.exception.status, 415)

    def test_monitor_forwards_model_positive_without_route_exemptions(self):
        middleware = AttackDetectionMiddleware.__new__(AttackDetectionMiddleware)
        middleware.pipeline, middleware.mode = "structured", "monitor"
        middleware.max_body_bytes, middleware.explain_blocks = 16384, False
        middleware.get_response = lambda request: HttpResponse("downstream")
        from unittest.mock import Mock
        middleware.detector = Mock()
        middleware.detector.predict.return_value = DetectionResult(.99, True, .1, 0, "safe representation", ())
        request = RequestFactory().get("/never_seen_route/")
        self.assertEqual(middleware(request).status_code, 200)
        middleware.detector.predict.assert_called_once()
        self.assertTrue(request.is_attack)
        middleware.mode = "block"
        self.assertEqual(middleware(RequestFactory().get("/never_seen_route/", HTTP_ACCEPT="application/json")).status_code, 403)


@override_settings(WAF_PIPELINE="structured", WAF_MODE="monitor", WAF_SAFE_EMPTY_PATHS=(),
                   WAF_CANDIDATE_DIR=Path(__file__).resolve().parents[2] / "artifacts/request_v2")
class StructuredFlowTests(TestCase):
    def test_actual_login_and_password_change_without_legacy_exceptions(self):
        from django.contrib.auth.models import User
        password = "Synthetic!'<script> OR 1=1--"
        user = User.objects.create_user("24bce0000", password=password)
        client = Client(enforce_csrf_checks=True)
        with patch.object(AttackDetectionMiddleware, "_safe_navigation", side_effect=AssertionError("Legacy bypass used")):
            response = client.get("/login/")
            self.assertEqual(response.status_code, 200)
            self.assertTrue(hasattr(response.wsgi_request, "attack_score"))
            token = client.cookies["csrftoken"].value
            response = client.post("/login/", {"username": user.username, "password": password,
                                               "csrfmiddlewaretoken": token})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(client.session["_auth_user_id"], str(user.pk))
            self.assertNotIn("synthetic", response.wsgi_request.attack_detection.inspected_text)
            response = client.get("/password_change/")
            self.assertEqual(response.status_code, 200)
            token = client.cookies["csrftoken"].value
            fields = {"old_password": password, "new_password1": "Replacement!2409",
                      "new_password2": "Replacement!2409"}
            self.assertEqual(client.post("/password_change/", fields).status_code, 403)
            fields["csrfmiddlewaretoken"] = token
            self.assertEqual(client.post("/password_change/", fields).status_code, 302)
            user.refresh_from_db()
            self.assertTrue(user.check_password("Replacement!2409"))

    def test_model_still_scores_unknown_routes_and_payload_in_monitor_mode(self):
        middleware = AttackDetectionMiddleware(lambda request: HttpResponse("allowed"))
        request = RequestFactory().get("/unseen_application/", {"q": "<script>alert(1)</script>"})
        self.assertEqual(middleware(request).status_code, 200)
        self.assertTrue(request.is_attack)
        self.assertIn("<script>", request.attack_detection.inspected_text)
