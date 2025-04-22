########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.views.mixins.ldap.group import GroupViewMixin
from core.ldap.types.group import LDAPGroupTypes
from core.views.mixins.logs import LogMixin
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from ldap3 import Entry as LDAPEntry, SUBTREE, Connection
from core.ldap.connector import LDAPConnector
from core.ldap.security_identifier import SID
from typing import Union
from logging import Logger

MockLDAPEntry = Union[LDAPEntry, MockType]
MockLDAPConnector = Union[LDAPConnector, MockType]

@pytest.fixture
def f_runtime_settings(mocker: MockerFixture, g_runtime_settings: RuntimeSettingsSingleton):
	mocker.patch("core.views.mixins.ldap.group.RuntimeSettings", g_runtime_settings)
	return g_runtime_settings

@pytest.fixture(autouse=True)
def f_logger(mocker: MockerFixture) -> Logger:
	m_logger = mocker.patch("core.views.mixins.ldap.group.logger")
	return m_logger


@pytest.fixture(autouse=True)
def f_log_mixin(mocker: MockerFixture) -> LogMixin:
	return mocker.patch(
		f"core.views.mixins.ldap.organizational_unit.DBLogMixin", mocker.MagicMock()
	)

@pytest.fixture
def f_distinguished_name(g_runtime_settings: RuntimeSettingsSingleton):
	return f"CN=test,{g_runtime_settings.LDAP_AUTH_SEARCH_BASE}"

@pytest.fixture
def f_group_mixin(mocker: MockerFixture) -> GroupViewMixin:
	m_request = mocker.Mock()
	m_request.user.id = 1
	m_mixin = GroupViewMixin()
	m_mixin.ldap_connection = mocker.MagicMock()
	m_mixin.request = m_request
	return m_mixin

@pytest.fixture
def f_group_entry(mocker: MockerFixture, f_distinguished_name: str) -> MockLDAPEntry:
	m_entry: MockLDAPEntry = mocker.MagicMock()
	m_entry.entry_dn = f_distinguished_name
	m_entry.distinguishedName.value = f_distinguished_name
	m_entry.distinguishedName.values = [f_distinguished_name]
	m_entry.objectSid.value = b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaa\x87\x04\x00\x00"
	m_entry.objectSid.values = [b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaa\x87\x04\x00\x00"]
	m_entry.objectSid.raw_values = [b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaa\x87\x04\x00\x00"]
	return m_entry

@pytest.fixture
def f_ldap_connection(mocker: MockerFixture):
	return mocker.Mock(spec=Connection)

@pytest.fixture(autouse=True)
def f_ldap_connector(mocker: MockerFixture, f_ldap_connection: MockType) -> MockLDAPConnector:
	m_connector = mocker.MagicMock(spec=LDAPConnector)
	m_connector.connection = f_ldap_connection
	m_connector.return_value.__enter__.return_value = m_connector
	mocker.patch("core.views.mixins.ldap.group.LDAPConnector", m_connector)
	return m_connector

class TestGetGroupTypes:
	@staticmethod
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

	@staticmethod
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


	@staticmethod
	def test_get_group_types_raises_value_error(
		f_group_mixin: GroupViewMixin,
	):
		with pytest.raises(ValueError, match="could not be cast"):
			f_group_mixin.get_group_types(group_type="a")

	@staticmethod
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

class TestGetGroupByRid:
	@staticmethod
	def test_get_group_by_rid_raises_on_none(f_group_mixin: GroupViewMixin):
		with pytest.raises(ValueError, match="rid cannot be None or False"):
			f_group_mixin.get_group_by_rid(rid=None)

	@staticmethod
	def test_get_group_by_rid_raises_on_bad_value(f_group_mixin: GroupViewMixin, f_logger: Logger):
		with pytest.raises(ValueError, match="Could not cast rid to int"):
			f_group_mixin.get_group_by_rid(rid="a")
		f_logger.exception.assert_called_once()
		f_logger.error.assert_called_once()

	@staticmethod
	@pytest.mark.parametrize(
		"rid, should_return_group_entry",
		(
			(1159, True),
			([1159], True),
			(514, False),
			([514], False),
		),
		ids=[
			"Matching RID Integer",
			"Matching RID Integer within List",
			"Non-Matching RID Integer",
			"Non-Matching RID Integer within List",
		]
	)
	def test_get_group_by_rid(
		mocker: MockerFixture,
		rid: int,
		should_return_group_entry: bool,
		f_group_mixin: GroupViewMixin,
		f_group_entry: MockLDAPEntry,
		f_ldap_connector: MockLDAPConnector,
		f_runtime_settings: RuntimeSettingsSingleton
	):
		# Mock result LDAPObject
		m_ldap_object = mocker.Mock()
		m_sid = SID(getattr(f_group_entry, "objectSid"))
		m_ldap_object.attributes = {
			"distinguishedName": f_group_entry.entry_dn,
			"objectSid": m_sid,
		}
		mocker.patch("core.views.mixins.ldap.group.LDAPObject", return_value=m_ldap_object)
		m_group_without_sid = mocker.MagicMock()
		m_group_without_sid.objectSid = None

		# Mock LDAP Connection
		m_connection = f_ldap_connector.connection
		m_connection.entries = [f_group_entry, m_group_without_sid]
		result = f_group_mixin.get_group_by_rid(rid=rid)
		m_connection.search.assert_called_once_with(
			search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
			search_filter="(objectClass=group)",
			search_scope=SUBTREE,
			attributes=["objectSid", "distinguishedName"],
		)
		if should_return_group_entry:
			assert isinstance(result, dict)
		else:
			assert result is None
