import pytest
from core.decorators.login import admin_required
from core.models.user import User
from rest_framework.request import Request
from core.exceptions.base import PermissionDenied


@pytest.fixture
def m_request(mocker):
	request = mocker.Mock(spec=Request)
	request.user = mocker.Mock(spec=User)
	return request


@pytest.mark.parametrize(
	"is_factory, is_superuser, expected",
	(
		# Test cases for admin_required
		(True, True, "response"),  # Superuser
		(
			False,
			True,
			"response",
		),  # Same as above, but using decorator as a factory
		(True, False, PermissionDenied),  # Not a superuser
	),
	ids=(
		"As Decorator (default), Superuser",
		"As Decorator Factory, Superuser",
		"Not Superuser",
	),
)
def test_admin_required(is_factory, is_superuser, expected, m_request, mocker):
	m_request.user.is_superuser = is_superuser
	m_view_func = mocker.Mock(return_value="response")

	if is_factory:
		decorated_func = admin_required(m_view_func)
	else:
		decorated_func = admin_required()(m_view_func)

	if expected == "response":
		result = decorated_func(None, m_request)
		assert result == "response"
	elif expected == PermissionDenied:
		with pytest.raises(PermissionDenied):
			decorated_func(None, m_request)

	# Verify the view function was called only if the user is a superuser
	if is_superuser:
		m_view_func.assert_called_once_with(None, m_request)
	else:
		m_view_func.assert_not_called()
