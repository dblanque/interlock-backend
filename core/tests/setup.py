# app/tests/test_setup.py

from django.test import TestCase
from rest_framework.test import APIClient

class TestModelSetup(TestCase):
    def setUp(self):
        self.client = APIClient()