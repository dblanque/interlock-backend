import re
import pytest
from pytest_mock import MockType
from core.models.application import (
	generate_client_id,
	generate_client_secret,
	Application,
)


@pytest.mark.django_db
class TestApplicationFunctions:
	def test_generate_client_id_uniqueness(self):
		"""Test that generated client IDs are unique"""
		# Generate a bunch of IDs
		generated_ids = {generate_client_id() for _ in range(50)}

		# Verify all are unique
		assert len(generated_ids) == 50

		# Verify they don't exist in database
		for client_id in generated_ids:
			assert not Application.objects.filter(client_id=client_id).exists()

	def test_generate_client_id_format(self):
		"""Test client ID has correct format"""
		client_id = generate_client_id()
		assert len(client_id) == 24
		assert re.fullmatch(r"[a-z0-9]{24}", client_id)

	def test_generate_client_id_collision_handling(self, mocker):
		"""Test it handles collisions properly"""
		# Mock the random string generation to return duplicates first
		mock_values = ["abc123", "abc123", "unique"]
		m_random_string: MockType = mocker.patch(
			"core.models.application.get_random_string", side_effect=mock_values
		)

		# Mock exists() to return True for first values
		m_queryset = mocker.MagicMock()
		m_queryset.exists.side_effect = [True, True, False]
		mocker.patch(
			"core.models.Application.objects.filter", return_value=m_queryset
		)

		# Second call should return the unique value
		result = generate_client_id()
		assert result == "unique"
		assert m_random_string.call_count == 3  # Called until unique found

	def test_generate_client_secret_length(self):
		"""Test client secret has correct length"""
		secret = generate_client_secret()
		# token_urlsafe(48) produces 64 chars (48 bytes base64 encoded)
		assert len(secret) == 64

	def test_generate_client_secret_uniqueness(self):
		"""Test secrets are different each time"""
		secrets = {generate_client_secret() for _ in range(50)}
		assert len(secrets) == 50

	def test_generate_client_secret_format(self):
		"""Test secret uses URL-safe characters"""
		secret = generate_client_secret()
		assert re.fullmatch(r"^[a-zA-Z0-9\-_]+$", secret)
