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
def test_disabled_user_unauthorized(
	url: str, method: str, disabled_user_client: APIClient
):
	method = getattr(disabled_user_client, method)
	response: Response = method(url)
	assert response.status_code == status.HTTP_401_UNAUTHORIZED
