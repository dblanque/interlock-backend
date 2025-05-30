import pytest
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status


@pytest.fixture(autouse=True)
def f_interlock_ldap_disabled(g_interlock_ldap_disabled):
	return g_interlock_ldap_disabled


def test_ldap_backend_disabled(
	g_ldap_domain_endpoints: tuple[str, str], admin_user_client: APIClient
):
	url, method = g_ldap_domain_endpoints
	method = getattr(admin_user_client, method.lower())
	response: Response = method(url)
	assert response.status_code == status.HTTP_418_IM_A_TEAPOT
