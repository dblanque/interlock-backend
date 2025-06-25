import pytest
from pytest_mock import MockerFixture
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.urls import resolve


@pytest.fixture(autouse=True)
def f_interlock_ldap_disabled(g_interlock_ldap_disabled):
	return g_interlock_ldap_disabled


def test_ldap_backend_disabled(
	g_ldap_domain_endpoints: tuple[str, str], admin_user_client: APIClient
):
	url, method = g_ldap_domain_endpoints
	method = getattr(admin_user_client, method.lower())
	response: Response = method(url.format(pk=0))
	assert response.status_code == status.HTTP_418_IM_A_TEAPOT

def test_ldap_backend_disabled_ignored(
	mocker: MockerFixture,
	g_non_ldap_domain_endpoints: tuple[str, str],
	admin_user_client: APIClient,
):
	url, method = g_non_ldap_domain_endpoints
	url = url.format(pk=0)
	match = resolve(url)
	view_func = match.func

	# For class-based views, get the actual method (get/post/etc.)
	if hasattr(view_func, 'cls'):
		view_class = view_func.cls
		view_method_name = view_func.actions.get(method.lower())
		view_method = getattr(view_class, view_method_name)
	else:
		view_method = view_func

	mocker.patch.object(
        (
			view_method.__self__
		 	if hasattr(view_method, '__self__')
		 	else view_class
		),
		view_method.__name__,
		return_value=Response(status=status.HTTP_204_NO_CONTENT),
	)
	method = getattr(admin_user_client, method.lower())
	response: Response = method(url)
	assert response.status_code == status.HTTP_204_NO_CONTENT
