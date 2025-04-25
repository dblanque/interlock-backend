import pytest
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status

@pytest.fixture(autouse=True)
def f_interlock_ldap_disabled(g_interlock_ldap_disabled):
	return g_interlock_ldap_disabled

@pytest.mark.parametrize(
	"url, method",
	(
		("/api/ldap/record/insert/", "post"),
		("/api/ldap/record/update/", "put"),
		("/api/ldap/record/delete/", "post"),
	),
)
def test_ldap_backend_disabled(url: str, method: str, admin_user_client: APIClient):
	method = getattr(admin_user_client, method)
	response: Response = method(url)
	assert response.status_code == status.HTTP_418_IM_A_TEAPOT
