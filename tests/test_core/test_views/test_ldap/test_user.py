import pytest
from rest_framework import status
from core.models.user import User
from core.views.mixins.ldap.user import UserViewLDAPMixin
from core.ldap.connector import LDAPConnector
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTING_ENABLE_LDAP,
	TYPE_BOOL
)

@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled():
	# Fake LDAP Enabled
	InterlockSetting.objects.create(
		name=INTERLOCK_SETTING_ENABLE_LDAP,
		type=TYPE_BOOL,
		value=True
	)

@pytest.mark.django_db
class TestLDAPUserViewSet:

	@pytest.mark.parametrize(
		"user_client_fixture, expected_code",
		(
			("admin_user_client", status.HTTP_200_OK),
			("normal_user_client", status.HTTP_403_FORBIDDEN),
		),
	)
	def test_list_users_success(self, user_client_fixture, expected_code, mocker, request):
		"""Test successful user listing"""
		client = request.getfixturevalue(user_client_fixture)

		# Mock LDAP connection and data
		m_ldap_users = {
			"users": [{"username": "testuser", "is_enabled": True}],
			"headers": ["username", "is_enabled"]
		}

		# Patch the LDAPConnector context manager
		m_connector = mocker.patch('core.views.ldap.user.LDAPConnector')
		m_connector.return_value.__enter__.return_value.connection = mocker.MagicMock()
		
		# Patch the ldap_user_list method to return our mock data
		mocker.patch.object(
			UserViewLDAPMixin,
			'ldap_user_list',
			return_value=m_ldap_users
		)

		# Make API call
		response = client.get('/api/ldap/users/')
		
		# Assertions
		assert response.status_code == expected_code
		if expected_code == status.HTTP_200_OK:
			assert response.data['code'] == 0
			assert len(response.data['users']) == 1
			assert 'username' in response.data['headers']

	def test_list_users_unauthenticated(self, api_client):
		"""Test unauthenticated access"""
		response = api_client.get('/api/ldap/users/')
		assert response.status_code == status.HTTP_401_UNAUTHORIZED

	def test_list_users_ldap_error(self, admin_user_client, mocker):
		"""Test LDAP connection failure"""
		# Mock LDAPConnector to raise an exception
		mocker.patch("core.views.ldap.user.LDAPConnector.bind", side_effect=Exception)

		response = admin_user_client.get('/api/ldap/users/')
		assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
