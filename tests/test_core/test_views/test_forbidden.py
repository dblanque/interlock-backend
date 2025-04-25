import pytest
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status

@pytest.mark.parametrize(
	"url, method",
	(
		("/api/ldap/record/insert/", "post"),
		("/api/ldap/record/update/", "put"),
		("/api/ldap/record/delete/", "post"),
	),
)
def test_normal_user_forbidden(url: str, method: str, normal_user_client: APIClient):
	method = getattr(normal_user_client, method)
	response: Response = method(url)
	assert response.status_code == status.HTTP_403_FORBIDDEN
