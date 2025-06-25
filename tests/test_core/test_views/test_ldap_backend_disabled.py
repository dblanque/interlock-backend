import pytest
from pytest_mock import MockerFixture
from rest_framework.test import APIClient
from rest_framework import status
from .endpoint_utils import endpoint_test_fn

@pytest.fixture(autouse=True)
def f_interlock_ldap_disabled(g_interlock_ldap_disabled):
	return g_interlock_ldap_disabled

@pytest.mark.django_db
def test_ldap_backend_endpoints_return_teapot(
	mocker: MockerFixture,
	g_ldap_domain_endpoints: tuple[str, str],
	admin_user_client: APIClient,
):
	url, method = g_ldap_domain_endpoints
	endpoint_test_fn(
		mocker=mocker,
		api_client=admin_user_client,
		url=url,
		method=method,
		expected_code=status.HTTP_418_IM_A_TEAPOT,
	)

def test_ldap_backend_endpoints_return_ok(
	mocker: MockerFixture,
	g_non_ldap_domain_endpoints: tuple[str, str],
	admin_user_client: APIClient,
):
	url, method = g_non_ldap_domain_endpoints
	endpoint_test_fn(
		mocker=mocker,
		api_client=admin_user_client,
		url=url,
		method=method,
		expected_code=status.HTTP_200_OK,
	)