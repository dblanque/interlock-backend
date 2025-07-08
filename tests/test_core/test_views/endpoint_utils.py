from pytest_mock import MockerFixture
from rest_framework.response import Response
from rest_framework.test import APIClient
from django.urls import resolve


def endpoint_test_fn(
	mocker: MockerFixture,
	api_client: APIClient,
	url: str,
	method: str,
	expected_code: int,
):
	url = url.format(pk=0)
	match = resolve(url)
	view_func = match.func

	# For class-based views, get the actual method (get/post/etc.)
	if hasattr(view_func, "cls"):
		view_class = view_func.cls
		view_method_name = view_func.actions.get(method.lower())
		view_method = getattr(view_class, view_method_name)
	else:
		view_method = view_func

	mocker.patch.object(
		(
			view_method.__self__
			if hasattr(view_method, "__self__")
			else view_class
		),
		view_method.__name__,
		return_value=Response(status=expected_code),
	)
	method = getattr(api_client, method.lower())
	response: Response = method(url)
	assert response.status_code == expected_code
