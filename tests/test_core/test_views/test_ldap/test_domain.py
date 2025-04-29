########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture
################################################################################
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.models.user import User
from core.models.interlock_settings import InterlockSetting, INTERLOCK_SETTING_ENABLE_LDAP
from core.views.ldap.domain import LDAPDomainViewSet
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from core.models.validators.ldap import domain_validator

@pytest.fixture
def f_runtime_settings(
	mocker: MockerFixture,
	g_runtime_settings: RuntimeSettingsSingleton
):
	mocker.patch("core.views.ldap.domain.RuntimeSettings", g_runtime_settings)
	return g_runtime_settings

@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled(g_interlock_ldap_enabled):
	return g_interlock_ldap_enabled

class TestDetailsEndpoint:
	endpoint = "/api/ldap/domain/details/"

	def test_success_with_defaults(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		mocker.patch("core.views.ldap.domain.INTERLOCK_DEBUG", False)
		response: Response = admin_user_client.get(self.endpoint)
		details: dict = response.data.get("details")
		assert response.status_code == status.HTTP_200_OK
		assert details.get("realm") == ""
		assert details.get("name") == ""
		assert details.get("basedn") == ""
		assert details.get("user_selector") == "sAMAccountName"
		assert not details.get("debug", None)

	def test_success_with_debug(self, mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch("core.views.ldap.domain.INTERLOCK_DEBUG", True)
		response: Response = admin_user_client.get(self.endpoint)
		details: dict = response.data.get("details")
		assert response.status_code == status.HTTP_200_OK
		assert details.get("debug") == True

	def test_success(
		self,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
		admin_user_client: APIClient,
	):
		mocker.patch("core.views.ldap.domain.INTERLOCK_DEBUG", False)
		m_domain = "example.org"
		m_realm = "EXMPLORG"
		m_search = "dc=example,dc=org"
		f_runtime_settings.LDAP_DOMAIN = m_domain
		f_runtime_settings.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN = m_realm
		f_runtime_settings.LDAP_AUTH_SEARCH_BASE = m_search

		response: Response = admin_user_client.get(self.endpoint)
		details: dict = response.data.get("details")
		assert response.status_code == status.HTTP_200_OK
		assert details.get("name") == m_domain
		assert details.get("realm") == m_realm
		assert details.get("basedn") == m_search
		assert details.get("user_selector") == "sAMAccountName"
		assert not details.get("debug", None)

	def test_without_interlock_ldap_setting(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		mocker.patch("core.views.ldap.domain.INTERLOCK_DEBUG", False)
		InterlockSetting.objects.filter(name=INTERLOCK_SETTING_ENABLE_LDAP).delete()
		response: Response = admin_user_client.get(self.endpoint)
		details: dict = response.data.get("details")
		assert response.status_code == status.HTTP_200_OK
		assert details.get("realm") == ""
		assert details.get("name") == ""
		assert details.get("basedn") == ""
		assert details.get("user_selector") == "sAMAccountName"
		assert not details.get("debug", None)


class TestZonesEndpoint:
	endpoint = "/api/ldap/domain/zones/"

	@pytest.mark.parametrize(
		"domain, expects_default, expected_domain",
		(
			("", True, None),
			("example.org", False, "example.org"),
		),
	)
	def test_success(
		self,
		domain: str,
		expects_default: bool,
		expected_domain: str,
		mocker: MockerFixture,
		f_runtime_settings: RuntimeSettingsSingleton,
		admin_user: User,
		admin_user_client: APIClient,
	):
		m_result = "mock_result"
		m_get_zone_records = mocker.patch.object(
			LDAPDomainViewSet, "get_zone_records", return_value=m_result)
		m_data = {"filter":{
			"dnsZone": domain
		}}
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json"
		)
		if expects_default:
			m_get_zone_records.assert_called_once_with(
				user=admin_user,
				target_zone=f_runtime_settings.LDAP_DOMAIN
			)
		else:
			m_get_zone_records.assert_called_once_with(
				user=admin_user,
				target_zone=expected_domain
			)
		data: dict = response.data.get("data")
		assert response.status_code == status.HTTP_200_OK
		assert data == m_result

	@pytest.mark.parametrize(
		"bad_value",
		(
			"a_bad_domain@!",
			"bad.domain.",
		),
	)
	def test_raises_bad_domain(
		self,
		bad_value: str,
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		m_result = "mock_result"
		m_get_zone_records = mocker.patch.object(
			LDAPDomainViewSet, "get_zone_records", return_value=m_result)
		m_data = {"filter":{
			"dnsZone": bad_value
		}}
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json"
		)
		m_get_zone_records.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "dns_field_validator_failed"

	def test_raises_domain_not_in_request(
		self,
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		m_result = "mock_result"
		m_get_zone_records = mocker.patch.object(
			LDAPDomainViewSet, "get_zone_records", return_value=m_result)
		m_data = {"filter":{}}
		response: Response = admin_user_client.post(
			self.endpoint,
			data=m_data,
			format="json"
		)
		m_get_zone_records.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "dns_zone_missing"

class TestInsertEndpoint:
	endpoint = "/api/ldap/domain/insert/"

	def test_raises_no_target_zone(self, admin_user_client: APIClient):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={},
			format="json"
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "dns_zone_missing"

	@pytest.mark.parametrize(
		"bad_value",
		(
			"example.",
			"example!@#",
			"bad.example.com.",
		),
	)
	def test_validation_raises(
		self,
		mocker: MockerFixture,
		bad_value: str,
		admin_user_client: APIClient
	):
		m_insert_zone = mocker.patch.object(LDAPDomainViewSet, "insert_zone", return_value="mock_result")
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"dnsZone": bad_value},
			format="json"
		)
		m_insert_zone.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "dns_field_validator_failed"

	@pytest.mark.parametrize(
		"bad_value",
		(
			"+f_runtime_settings.LDAP_DOMAIN",
			"RootDNSServers",
		),
	)
	def test_validation_raises_zone_exists(
		self,
		mocker: MockerFixture,
		bad_value: str,
		admin_user_client: APIClient,
		request: FixtureRequest
	):
		if bad_value.startswith("+"):
			bad_value_split = bad_value.split(".")
			bad_value_fixture = request.getfixturevalue(bad_value_split[0][1:])
			bad_value = getattr(bad_value_fixture, bad_value_split[1])
		m_insert_zone = mocker.patch.object(LDAPDomainViewSet, "insert_zone", return_value="mock_result")
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"dnsZone": bad_value},
			format="json"
		)
		m_insert_zone.assert_not_called()
		assert response.status_code == status.HTTP_409_CONFLICT
		assert response.data.get("code") == "dns_zone_exists"

	def test_success(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
	):
		m_insert_zone = mocker.patch.object(LDAPDomainViewSet, "insert_zone", return_value="mock_result")
		m_domain_validator = mocker.patch("core.views.ldap.domain.domain_validator", wraps=domain_validator)
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"dnsZone": "example.org"},
			format="json"
		)
		m_insert_zone.assert_called_once_with(
			user=admin_user, target_zone="example.org")
		m_domain_validator.assert_called_once_with("example.org")
		assert response.status_code == status.HTTP_200_OK

class TestDeleteEndpoint:
	endpoint = "/api/ldap/domain/delete/"

	def test_raises_no_target_zone(self, admin_user_client: APIClient):
		response: Response = admin_user_client.post(
			self.endpoint,
			data={},
			format="json"
		)
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "dns_zone_missing"

	@pytest.mark.parametrize(
		"bad_value",
		(
			"example.",
			"example!@#",
			"bad.example.com.",
		),
	)
	def test_validation_raises(self, mocker: MockerFixture, bad_value: str, admin_user_client: APIClient):
		m_delete_zone = mocker.patch.object(LDAPDomainViewSet, "delete_zone", return_value="mock_result")
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"dnsZone": bad_value},
			format="json"
		)
		m_delete_zone.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "dns_field_validator_failed"

	@pytest.mark.parametrize(
		"bad_value",
		(
			"+f_runtime_settings.LDAP_DOMAIN",
			"RootDNSServers",
		),
	)
	def test_validation_raises_zone_exists(self, mocker: MockerFixture, bad_value: str, admin_user_client: APIClient, request: FixtureRequest):
		if bad_value.startswith("+"):
			bad_value_split = bad_value.split(".")
			bad_value_fixture = request.getfixturevalue(bad_value_split[0][1:])
			bad_value = getattr(bad_value_fixture, bad_value_split[1])
		m_delete_zone = mocker.patch.object(LDAPDomainViewSet, "delete_zone", return_value="mock_result")
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"dnsZone": bad_value},
			format="json"
		)
		m_delete_zone.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "dns_zone_not_deletable"

	def test_success(
		self,
		mocker: MockerFixture,
		admin_user: User,
		admin_user_client: APIClient,
	):
		m_delete_zone = mocker.patch.object(LDAPDomainViewSet, "delete_zone", return_value=("mock_zone_result","mock_forest_result"))
		m_domain_validator = mocker.patch("core.views.ldap.domain.domain_validator", wraps=domain_validator)
		response: Response = admin_user_client.post(
			self.endpoint,
			data={"dnsZone": "example.org"},
			format="json"
		)
		m_delete_zone.assert_called_once_with(
			user=admin_user, target_zone="example.org")
		m_domain_validator.assert_called_once_with("example.org")
		assert response.status_code == status.HTTP_200_OK
