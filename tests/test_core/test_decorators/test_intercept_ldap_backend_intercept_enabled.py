import pytest
from unittest.mock import Mock
from core.decorators.intercept import ldap_backend_intercept
from core.exceptions.base import LDAPBackendDisabled
from django.core.exceptions import ObjectDoesNotExist


@pytest.fixture
def mock_request(mocker) -> Mock:
	return mocker.Mock()


@pytest.fixture
def interlock_setting_get():
	return "core.models.interlock_settings.InterlockSetting.objects.get"


@pytest.mark.parametrize(
	"is_factory",
	(
		(True,),
		(False,),
	),
)
def test_ldap_backend_intercept_enabled(is_factory, mock_request, interlock_setting_get, mocker):
	# Mock InterlockSetting.objects.get to return an enabled LDAP setting
	mock_ldap_setting = mocker.Mock()
	mock_ldap_setting.value = True
	mocker.patch(interlock_setting_get, return_value=mock_ldap_setting)

	m_view_func = mocker.Mock(return_value="response")
	if is_factory is True:
		decorated_func = ldap_backend_intercept(m_view_func)
	else:
		decorated_func = ldap_backend_intercept()(m_view_func)
	result = decorated_func(None, mock_request)

	m_view_func.assert_called_once_with(None, mock_request)
	assert result == "response"


def test_ldap_backend_intercept_disabled(mock_request, interlock_setting_get, mocker):
	# Mock InterlockSetting.objects.get to return a disabled LDAP setting
	mock_ldap_setting = mocker.Mock()
	mock_ldap_setting.value = False
	mocker.patch(interlock_setting_get, return_value=mock_ldap_setting)
	m_view_func = mocker.Mock(return_value="response")
	decorated_func = ldap_backend_intercept(m_view_func)
	with pytest.raises(LDAPBackendDisabled):
		decorated_func(None, mock_request)


def test_ldap_backend_intercept_setting_missing(mock_request, interlock_setting_get, mocker):
	# Mock InterlockSetting.objects.get to raise ObjectDoesNotExist
	mocker.patch(interlock_setting_get, side_effect=ObjectDoesNotExist)

	m_view_func = mocker.Mock(return_value="response")
	decorated_func = ldap_backend_intercept(m_view_func)
	with pytest.raises(LDAPBackendDisabled):
		decorated_func(None, mock_request)
