import sys
import os
import unittest

# Adjust the path so we can import modules from the 'app' directory
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app"))

from fastapi.testclient import TestClient
from main import app

class TestPhishingDetectorMLService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a TestClient instance
        cls.client = TestClient(app)

    def test_health_check(self):
        """Test the health check endpoint returns 200 and correct details"""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertEqual(data.get("status"), "ok")
        self.assertEqual(data.get("model"), "LightGBM")
        self.assertIn("version", data)

    def test_predict_empty_url(self):
        """Test prediction with an empty URL returns a 400 Bad Request"""
        response = self.client.post("/predict", json={"url": "   "})
        self.assertEqual(response.status_code, 400)
        self.assertIn("detail", response.json())

    def test_predict_safe_url(self):
        """Test prediction for a standard safe URL like google.com"""
        response = self.client.post("/predict", json={"url": "https://www.google.com"})
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertIn("label", data)
        self.assertIn("status", data)
        self.assertIn("confidence", data)
        self.assertEqual(data.get("status"), "safe")

    def test_predict_phishing_url(self):
        """Test prediction returns appropriate response structures"""
        response = self.client.post("/predict", json={"url": "http://phishing-test-site.com"})
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertIn("label", data)
        self.assertIn("status", data)
        self.assertIn("confidence", data)

if __name__ == "__main__":
    unittest.main()
