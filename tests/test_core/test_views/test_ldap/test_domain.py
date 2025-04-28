########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.models.user import User
from core.models.interlock_settings import InterlockSetting, INTERLOCK_SETTING_ENABLE_LDAP
from core.views.ldap.domain import LDAPDomainViewSet
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status

@pytest.fixture
def f_runtime_settings(
	mocker: MockerFixture,
	g_runtime_settings: RuntimeSettingsSingleton
):
	mocker.patch("core.views.ldap.domain.RuntimeSettings", g_runtime_settings)
	return g_runtime_settings

@pytest.fixture
def f_viewset():
	return LDAPDomainViewSet()

@pytest.fixture(autouse=True)
def f_interlock_ldap_enabled(g_interlock_ldap_enabled):
	return g_interlock_ldap_enabled

class TestDetailsEndpoint:
	@staticmethod
	def test_success_with_defaults(
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		mocker.patch("core.views.ldap.domain.INTERLOCK_DEBUG", False)
		response: Response = admin_user_client.get("/api/ldap/domain/details/")
		details: dict = response.data.get("details")
		assert response.status_code == status.HTTP_200_OK
		assert details.get("realm") == ""
		assert details.get("name") == ""
		assert details.get("basedn") == ""
		assert details.get("user_selector") == "sAMAccountName"
		assert not details.get("debug", None)

	@staticmethod
	def test_success_with_debug(mocker: MockerFixture, admin_user_client: APIClient):
		mocker.patch("core.views.ldap.domain.INTERLOCK_DEBUG", True)
		response: Response = admin_user_client.get("/api/ldap/domain/details/")
		details: dict = response.data.get("details")
		assert response.status_code == status.HTTP_200_OK
		assert details.get("debug") == True

	@staticmethod
	def test_success(
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

		response: Response = admin_user_client.get("/api/ldap/domain/details/")
		details: dict = response.data.get("details")
		assert response.status_code == status.HTTP_200_OK
		assert details.get("name") == m_domain
		assert details.get("realm") == m_realm
		assert details.get("basedn") == m_search
		assert details.get("user_selector") == "sAMAccountName"
		assert not details.get("debug", None)

	@staticmethod
	def test_without_interlock_ldap_setting(
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		mocker.patch("core.views.ldap.domain.INTERLOCK_DEBUG", False)
		InterlockSetting.objects.filter(name=INTERLOCK_SETTING_ENABLE_LDAP).delete()
		response: Response = admin_user_client.get("/api/ldap/domain/details/")
		details: dict = response.data.get("details")
		assert response.status_code == status.HTTP_200_OK
		assert details.get("realm") == ""
		assert details.get("name") == ""
		assert details.get("basedn") == ""
		assert details.get("user_selector") == "sAMAccountName"
		assert not details.get("debug", None)


class TestZonesEndpoint:
	@staticmethod
	@pytest.mark.parametrize(
		"domain, expects_default, expected_domain",
		(
			("", True, None),
			("example.org", False, "example.org"),
		),
	)
	def test_success(
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
			"/api/ldap/domain/zones/",
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

	@staticmethod
	@pytest.mark.parametrize(
		"bad_value",
		(
			"a_bad_domain@!",
			"bad.domain.",
		),
	)
	def test_raises_bad_domain(
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
			"/api/ldap/domain/zones/",
			data=m_data,
			format="json"
		)
		m_get_zone_records.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "dns_field_validator_failed"

	@staticmethod
	def test_raises_domain_not_in_request(
		mocker: MockerFixture,
		admin_user_client: APIClient,
	):
		m_result = "mock_result"
		m_get_zone_records = mocker.patch.object(
			LDAPDomainViewSet, "get_zone_records", return_value=m_result)
		m_data = {"filter":{}}
		response: Response = admin_user_client.post(
			"/api/ldap/domain/zones/",
			data=m_data,
			format="json"
		)
		m_get_zone_records.assert_not_called()
		assert response.status_code == status.HTTP_400_BAD_REQUEST
		assert response.data.get("code") == "dns_zone_missing"

class TestInsertEndpoint:
	pass

class TestDeleteEndpoint:
	pass
