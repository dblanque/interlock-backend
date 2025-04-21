########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.views.mixins.ldap.group import GroupViewMixin
from core.ldap.types.group import LDAPGroupTypes
from core.views.mixins.logs import LogMixin


@pytest.fixture
def f_logger(mocker: MockerFixture):
	return mocker.patch("core.views.mixins.ldap.organizational_unit.logger")


@pytest.fixture(autouse=True)
def f_log_mixin(mocker: MockerFixture) -> LogMixin:
	return mocker.patch(
		f"core.views.mixins.ldap.organizational_unit.DBLogMixin", mocker.MagicMock()
	)

@pytest.fixture
def f_group_mixin(mocker: MockerFixture) -> GroupViewMixin:
	m_request = mocker.Mock()
	m_request.user.id = 1
	m_mixin = GroupViewMixin()
	m_mixin.ldap_connection = mocker.MagicMock()
	m_mixin.request = m_request
	return m_mixin

@pytest.mark.parametrize(
	"group_type, expected_types",
	(
		(
			-LDAPGroupTypes.GROUP_SECURITY.value + LDAPGroupTypes.GROUP_SYSTEM.value,
			[LDAPGroupTypes.GROUP_SECURITY.name, LDAPGroupTypes.GROUP_SYSTEM.name]
		),
		(
			-LDAPGroupTypes.GROUP_SECURITY.value + LDAPGroupTypes.GROUP_GLOBAL.value,
			[LDAPGroupTypes.GROUP_SECURITY.name, LDAPGroupTypes.GROUP_GLOBAL.name]
		),
		(
			-LDAPGroupTypes.GROUP_SECURITY.value + LDAPGroupTypes.GROUP_DOMAIN_LOCAL.value,
			[LDAPGroupTypes.GROUP_SECURITY.name, LDAPGroupTypes.GROUP_DOMAIN_LOCAL.name]
		),
		(
			-LDAPGroupTypes.GROUP_SECURITY.value + LDAPGroupTypes.GROUP_UNIVERSAL.value,
			[LDAPGroupTypes.GROUP_SECURITY.name, LDAPGroupTypes.GROUP_UNIVERSAL.name]
		),
		(
			LDAPGroupTypes.GROUP_SYSTEM.value,
			[LDAPGroupTypes.GROUP_DISTRIBUTION.name, LDAPGroupTypes.GROUP_SYSTEM.name]
		),
		(
			LDAPGroupTypes.GROUP_GLOBAL.value,
			[LDAPGroupTypes.GROUP_DISTRIBUTION.name, LDAPGroupTypes.GROUP_GLOBAL.name]
		),
		(
			LDAPGroupTypes.GROUP_DOMAIN_LOCAL.value,
			[LDAPGroupTypes.GROUP_DISTRIBUTION.name, LDAPGroupTypes.GROUP_DOMAIN_LOCAL.name]
		),
		(
			LDAPGroupTypes.GROUP_UNIVERSAL.value,
			[LDAPGroupTypes.GROUP_DISTRIBUTION.name, LDAPGroupTypes.GROUP_UNIVERSAL.name]
		),
		(
			LDAPGroupTypes.GROUP_DISTRIBUTION.value,
			[LDAPGroupTypes.GROUP_DISTRIBUTION.name],
		),
	),
	ids=[
		"GROUP_SECURITY, GROUP_SYSTEM",
		"GROUP_SECURITY, GROUP_GLOBAL",
		"GROUP_SECURITY, GROUP_DOMAIN_LOCAL",
		"GROUP_SECURITY, GROUP_UNIVERSAL",
		"GROUP_DISTRIBUTION, GROUP_SYSTEM",
		"GROUP_DISTRIBUTION, GROUP_GLOBAL",
		"GROUP_DISTRIBUTION, GROUP_DOMAIN_LOCAL",
		"GROUP_DISTRIBUTION, GROUP_UNIVERSAL",
		"GROUP_DISTRIBUTION",
	]
)
def test_get_group_types(
	group_type: int,
	expected_types: list[str],
	f_group_mixin: GroupViewMixin,
):
	assert f_group_mixin.get_group_types(group_type=group_type) == expected_types

@pytest.mark.parametrize(
	"bad_value_type",
	(
		False,
		None,
		[],
		{},
		b"some_bytes",
	),
)
def test_get_group_types_raises_type_error(
	bad_value_type: int,
	f_group_mixin: GroupViewMixin,
):
	with pytest.raises(TypeError, match="must be of type"):
		f_group_mixin.get_group_types(group_type=bad_value_type)

def test_get_group_types_raises_value_error(
	f_group_mixin: GroupViewMixin,
):
	with pytest.raises(ValueError, match="could not be cast"):
		f_group_mixin.get_group_types(group_type="a")

@pytest.mark.parametrize(
	"bad_group_type",
	(
		239,
		LDAPGroupTypes.GROUP_SECURITY.value + LDAPGroupTypes.GROUP_GLOBAL.value,
	),
	ids=[
		"Mock invalid integer: 239",
		"Positive Type GROUP_SECURITY instead of Negative.",
	]
)
def test_get_group_types_raises_exc(
	bad_group_type: int,
	f_group_mixin: GroupViewMixin,
):
	with pytest.raises(ValueError, match="group type integer"):
		f_group_mixin.get_group_types(group_type=bad_group_type)