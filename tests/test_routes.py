
import unittest

from app import app


class TestValidationRoutes(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_homepage_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SecureScan", response.data)

    def test_valid_https_url(self):
        response = self.client.post(
            "/api/validate",
            json={"url": "https://example.com"}
        )

        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertTrue(data["valid"])
        self.assertEqual(data["hostname"], "example.com")
        self.assertEqual(data["scheme"], "https")

    def test_unsupported_protocol_is_rejected(self):
        response = self.client.post(
            "/api/validate",
            json={"url": "ftp://example.com"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["valid"])

    def test_missing_url_is_rejected(self):
        response = self.client.post(
            "/api/validate",
            json={}
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_non_json_request_is_rejected(self):
        response = self.client.post(
            "/api/validate",
            data="url=https://example.com",
            content_type="application/x-www-form-urlencoded"
        )

        self.assertEqual(response.status_code, 415)
        self.assertIn("error", response.get_json())

    def test_invalid_json_body_is_rejected(self):
        response = self.client.post(
            "/api/validate",
            data="{invalid-json",
            content_type="application/json"
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_null_url_is_rejected(self):
        response = self.client.post(
            "/api/validate",
            json={"url": None}
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["valid"])

    def test_wrong_http_method_is_rejected(self):
        response = self.client.get("/api/validate")

        self.assertEqual(response.status_code, 405)


if __name__ == "__main__":
    unittest.main()
