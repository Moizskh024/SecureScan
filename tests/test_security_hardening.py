import unittest

from app import app


class TestSecurityHardening(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self):
        app.config["TESTING"] = False

    def test_invalid_json_is_rejected(self):
        response = self.client.post(
            "/api/validate",
            data='{"url": ',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_non_json_request_is_rejected(self):
        response = self.client.post(
            "/api/validate",
            data="https://example.com",
            content_type="text/plain",
        )

        self.assertEqual(response.status_code, 415)

    def test_missing_url_is_rejected(self):
        response = self.client.post(
            "/api/validate",
            json={},
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["valid"])

    def test_json_array_is_rejected(self):
        response = self.client.post(
            "/api/validate",
            json=["https://example.com"],
        )

        self.assertEqual(response.status_code, 400)

    def test_non_object_json_bodies_are_rejected(self):
        cases = [
            "null",
            "123",
            "true",
            '"hello"',
        ]

        for body in cases:
            with self.subTest(body=body):
                response = self.client.post(
                    "/api/validate",
                    data=body,
                    content_type="application/json",
                )

                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json()["error"],
                    "The request body must be a JSON object.",
                )
                self.assertFalse(
                    response.get_json()["valid"]
                )

    def test_oversized_request_is_rejected(self):
        response = self.client.post(
            "/api/validate",
            data='{"url":"' + ("a" * 20000) + '"}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 413)

    def test_get_method_not_allowed_for_api(self):
        response = self.client.get("/api/validate")

        self.assertEqual(response.status_code, 405)

    def test_missing_headers_field_is_rejected(self):
        response = self.client.post(
            "/api/analyze-headers",
            json={},
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["success"])

    def test_headers_as_list_are_rejected(self):
        response = self.client.post(
            "/api/analyze-headers",
            json={"headers": ["Content-Security-Policy"]},
        )

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
