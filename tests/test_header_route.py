
import unittest

from app import app


class TestHeaderAnalyzerRoute(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_valid_request(self):
        response = self.client.post(
            "/api/analyze-headers",
            json={"headers": {"X-Content-Type-Options": "nosniff"}}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["counts"]["total"], 6)
        self.assertIn("score", data)

    def test_missing_headers_field(self):
        response = self.client.post("/api/analyze-headers", json={})
        self.assertEqual(response.status_code, 400)

    def test_headers_must_be_a_dictionary(self):
        response = self.client.post(
            "/api/analyze-headers",
            json={"headers": []}
        )
        self.assertEqual(response.status_code, 400)

    def test_header_values_must_be_strings(self):
        response = self.client.post(
            "/api/analyze-headers",
            json={"headers": {"X-Frame-Options": None}}
        )
        self.assertEqual(response.status_code, 400)

    def test_non_json_request(self):
        response = self.client.post(
            "/api/analyze-headers",
            data="not json",
            content_type="text/plain"
        )
        self.assertEqual(response.status_code, 415)


if __name__ == "__main__":
    unittest.main()
