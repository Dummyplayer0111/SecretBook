from pathlib import Path
from urllib.parse import urlencode
from django.test import SimpleTestCase, RequestFactory, override_settings
from . import test_representation as _flows
from .payload_representation import components, represent
from .middleware import structured_request_text
from .structured_detector import load_candidate
from .payload_representation import SEPARATOR


class ComponentRepresentationTests(SimpleTestCase):
    def test_relative_urls_are_normalized_regardless_of_field_name(self):
        first = represent("GET", "/one/?" + urlencode({"next": "/admin/auth/user/"}))
        second = represent("GET", "/different/?" + urlencode({"destination": "/other/path/"}))
        self.assertEqual(first, second)
        self.assertIn("relative-url", first)

    def test_relative_url_payload_and_fragment_are_still_inspected(self):
        value = "/normal/path/?" + urlencode({"q": "<script>alert(1)</script>"}) + "#' OR 1=1--"
        text = represent("GET", "/entry/?" + urlencode({"next": value}))
        self.assertIn("<script>", text)
        self.assertIn("or 1=1--", text)

    def test_field_names_and_wrappers_share_payload_representation(self):
        value = "' OR 1=1--"
        query = components("GET", "/any/?" + urlencode({"q": value}))
        form = components("POST", "/new/", urlencode({"comment": value}), "application/x-www-form-urlencoded")
        self.assertEqual(query, form)

    def test_all_components_survive_and_nested_keys_are_visible(self):
        text = represent("POST", "/api/", '{"safe":"hello","<script>":{"inner":"text"},"password":"private"}', "application/json")
        self.assertIn("hello", text)
        self.assertIn("<script>", text)
        self.assertNotIn("private", text)

    def test_runtime_matches_training_for_form_and_json(self):
        for body, kind in [(urlencode({"username":"24bce0000", "password":"private"}), "application/x-www-form-urlencoded"),
                           ('{"text":"example","password":"private"}', "application/json")]:
            request = RequestFactory().generic("PUT", "/arbitrary/", body, content_type=kind)
            self.assertEqual(structured_request_text(request, 16384, component_mode=True), represent("PUT", "/arbitrary/", body, kind))
            self.assertEqual(request.body.decode(), body)

    def test_mismatched_candidate_version_is_rejected(self):
        directory = Path(__file__).resolve().parents[2] / "artifacts/request_v2"
        with self.assertRaisesRegex(ValueError, "versions differ"):
            load_candidate(directory, expected_version="request-components-relative-url-v3")

    def test_saved_component_cnn_scores_later_fields_and_maps_explanations(self):
        model = load_candidate(Path(__file__).resolve().parents[2] / "artifacts/request_v3",
                               expected_version="request-components-relative-url-v3")
        text = represent("POST", "/new/", urlencode({"title": "Notes", "body": "<script>alert(1)</script>"}),
                         "application/x-www-form-urlencoded")
        result = model.predict(text, explain=True)
        self.assertTrue(result.is_attack)
        individual = [model.predict(part, explain=False).score for part in text.split(SEPARATOR)]
        self.assertAlmostEqual(result.score, max(individual), places=5)
        self.assertTrue(result.influential_spans)
        for span in result.influential_spans:
            self.assertEqual(text[span.start:span.end], span.text)
            self.assertGreaterEqual(span.start, text.index(SEPARATOR) + len(SEPARATOR))


@override_settings(WAF_PIPELINE="components", WAF_MODE="monitor", WAF_SAFE_EMPTY_PATHS=(),
                   WAF_CANDIDATE_DIR=Path(__file__).resolve().parents[2] / "artifacts/request_v3")
class ComponentFlowTests(_flows.StructuredFlowTests):
    """Repeat real auth/CSRF flows with the independently selected v3 artifact."""
