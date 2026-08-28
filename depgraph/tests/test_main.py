import unittest

from app.main import app


class MainAppTests(unittest.TestCase):
    def test_application_metadata(self):
        self.assertEqual(app.title, "DepGraph")

    def test_expected_api_routes_exist(self):
        paths = {route.path for route in app.routes}
        self.assertIn("/api/health", paths)
        self.assertIn("/api/projects", paths)
        self.assertIn("/api/vulnerabilities/{cve_id}", paths)
        self.assertIn("/api/maintainer-risk", paths)

    def test_static_frontend_is_mounted(self):
        self.assertIn("", {route.path for route in app.routes})


if __name__ == "__main__":
    unittest.main()
