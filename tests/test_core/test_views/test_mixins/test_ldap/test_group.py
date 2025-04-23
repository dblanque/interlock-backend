########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.views.mixins.ldap.group import GroupViewMixin
from core.ldap.types.group import LDAPGroupTypes
from core.exceptions import ldap as exc_ldap, groups as exc_groups
from core.views.mixins.logs import LogMixin
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from ldap3 import Entry as LDAPEntry, SUBTREE, Connection
from core.ldap.connector import LDAPConnector
from core.ldap.filter import LDAPFilter
from core.ldap.security_identifier import SID
from core.models.choices.log import (
	LOG_ACTION_CREATE,
	LOG_ACTION_UPDATE,
	LOG_ACTION_DELETE,
	LOG_ACTION_READ,
	LOG_CLASS_GROUP,
	LOG_TARGET_ALL,
)
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
		f"core.views.mixins.ldap.group.DBLogMixin", mocker.MagicMock()
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
def f_sid_1():
	return b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaa\x87\x04\x00\x00"

@pytest.fixture
def f_sid_2():
	return b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x11^\xb3\x83j\x06\x94\x00\x80\xdbi\xaaR\x04\x00\x00"

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

@pytest.fixture
def f_ldap_search_base(f_runtime_settings: RuntimeSettingsSingleton):
	return f_runtime_settings.LDAP_AUTH_SEARCH_BASE

@pytest.fixture
def f_ldap_domain(f_runtime_settings: RuntimeSettingsSingleton):
	return f_runtime_settings.LDAP_DOMAIN

@pytest.fixture
def f_auth_field_username(f_runtime_settings: RuntimeSettingsSingleton):
	return f_runtime_settings.LDAP_AUTH_USER_FIELDS["username"]

@pytest.fixture
def fc_group_entry(mocker: MockerFixture, f_ldap_search_base, f_ldap_domain, f_sid_1):
	def maker(groupname="testgroup", **kwargs):
		if "spec" in kwargs:
			mock: LDAPEntry = mocker.MagicMock(spec=kwargs.pop("spec"))
		else:
			mock: LDAPEntry = mocker.MagicMock()
		mock.entry_attributes = []
		mock.entry_attributes_as_dict = {}
		attrs = {
			"distinguishedName": f"CN={groupname},OU=Groups,{f_ldap_search_base}",
			"member":[],
			"cn": groupname,
			"groupType": -LDAPGroupTypes.GROUP_SECURITY.value + LDAPGroupTypes.GROUP_GLOBAL.value,
			"objectSid": f_sid_1,
			"mail": f"mock@{f_ldap_domain}",
		} | kwargs
		for k, v in attrs.items():
			m_attr = mocker.Mock()
			m_attr.value = v
			m_attr.values = [v]
			if k == "objectSid":
				m_attr.raw_values = [v]
			setattr(mock, k, m_attr)
			mock.entry_attributes_as_dict[k] = [v]
			mock.entry_attributes.append(k)
		mock.entry_dn = attrs["distinguishedName"]
		return mock

	return maker

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
		fc_group_entry,
		f_ldap_connector: MockLDAPConnector,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		# Mock result LDAPObject
		m_group_entry = fc_group_entry()
		m_ldap_object = mocker.Mock()
		m_sid = SID(getattr(m_group_entry, "objectSid"))
		m_ldap_object.attributes = {
			"distinguishedName": m_group_entry.entry_dn,
			"objectSid": m_sid,
		}
		mocker.patch("core.views.mixins.ldap.group.LDAPObject", return_value=m_ldap_object)
		m_group_without_sid = mocker.MagicMock()
		m_group_without_sid.objectSid = None

		# Mock LDAP Connection
		m_connection = f_ldap_connector.connection
		m_connection.entries = [m_group_entry, m_group_without_sid]
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

class TestGroupMixinCRUD:
	@staticmethod
	def test_list(fc_group_entry, f_group_mixin: GroupViewMixin, f_log_mixin: LogMixin):
		f_group_mixin.ldap_filter_attr = ["cn", "distinguishedName", "groupType", "member"]
		f_group_mixin.ldap_filter_object = LDAPFilter.eq("objectClass", "group")
		m_group_1: LDAPEntry = fc_group_entry(groupname="Test Group 1")
		m_group_2: LDAPEntry = fc_group_entry(
			groupname="Test Group 2",
			groupType=LDAPGroupTypes.GROUP_DOMAIN_LOCAL.value,
			member=["mock_dn"]
		)
		f_group_mixin.ldap_connection.entries = [ m_group_1, m_group_2 ]
		groups, headers = f_group_mixin.list_groups()
		assert headers == ["cn", "groupType", "hasMembers"]
		assert len(groups) == 2
		assert groups[0].get("distinguishedName") == m_group_1.entry_dn
		assert groups[1].get("distinguishedName") == m_group_2.entry_dn
		assert groups[0].get("hasMembers") is False
		assert groups[1].get("hasMembers") is True
		assert groups[0].get("groupType") == [LDAPGroupTypes.GROUP_SECURITY.name, LDAPGroupTypes.GROUP_GLOBAL.name]
		assert groups[1].get("groupType") == [LDAPGroupTypes.GROUP_DISTRIBUTION.name, LDAPGroupTypes.GROUP_DOMAIN_LOCAL.name]
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_GROUP,
			log_target=LOG_TARGET_ALL,
		)

	@staticmethod
	def test_fetch(
		mocker: MockerFixture,
		fc_group_entry: LDAPEntry,
		f_group_mixin: GroupViewMixin,
		f_log_mixin: LogMixin,
		f_ldap_domain: str,
		f_ldap_search_base: str,
		f_auth_field_username: str,
	):
		m_common_name = "testgroup"
		m_member_dn = "mock_member_dn"
		m_group_entry = fc_group_entry(
			groupname=m_common_name,
			member=[ m_member_dn ]
		)
		f_group_mixin.ldap_connection.entries = [ m_group_entry ]
		f_group_mixin.ldap_filter_attr = ["cn", "mail", "member", "distinguishedName", "groupType", "objectSid"]
		f_group_mixin.ldap_filter_object = f"(&(objectClass=group)(distinguishedName={m_group_entry}))"

		# Mock LDAP Object Member
		m_ldap_user_object = mocker.Mock()
		m_ldap_user_attrs = {"attributes": "dict"}
		m_ldap_user_object.attributes = m_ldap_user_attrs
		m_ldap_object = mocker.Mock(return_value=m_ldap_user_object)
		mocker.patch("core.views.mixins.ldap.group.LDAPObject", m_ldap_object)

		group, headers = f_group_mixin.fetch_group()
		f_group_mixin.ldap_connection.search.assert_called_once_with(
			search_base=f_ldap_search_base,
			search_filter=f_group_mixin.ldap_filter_object,
			attributes=f_group_mixin.ldap_filter_attr,
		)
		m_ldap_object.assert_called_once_with(
			**{
				"connection": f_group_mixin.ldap_connection,
				"dn": m_member_dn,
				"ldap_attrs": [
					"cn",
					"distinguishedName",
					f_auth_field_username,
					"givenName",
					"sn",
					"objectCategory",
					"objectClass",
				],
			}
		)
		assert isinstance(group, dict)
		assert group.get("cn") == m_common_name
		assert group.get("mail") == f"mock@{f_ldap_domain}"
		assert group.get("member") == [ m_ldap_user_attrs ]
		assert group.get("groupType") == [LDAPGroupTypes.GROUP_SECURITY.name, LDAPGroupTypes.GROUP_GLOBAL.name]
		assert group.get("objectSid") == "S-1-5-21-2209570321-9700970-2859064192-1159"
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_GROUP,
			log_target=m_common_name,
		)
		assert set(headers) == {
			"cn",
			"mail",
			"member",
			"groupType",
			"objectSid",
		}

	@pytest.mark.parametrize(
		"p_group_data",
		(
			{
				"cn": "Test Group",
				"groupType": 1, # Mapped to Security
				"groupScope": 1, # Mapped to Domain Local
				"membersToAdd": [ "mock_user_dn" ],
			},
			{
				"cn": "Test Group",
				"groupType": 1, # Mapped to Security
				"groupScope": 1, # Mapped to Domain Local
			},
		),
	)
	def test_create(
		mocker: MockerFixture,
		p_group_data: dict,
		f_group_mixin: GroupViewMixin,
		f_log_mixin: LogMixin,
		f_ldap_search_base: str,
		f_auth_field_username: str,
	):
		f_group_mixin.ldap_connection.entries = []
		m_common_name = p_group_data["cn"]
		m_path = f"OU=Groups,{f_ldap_search_base}"
		m_group_data = p_group_data.copy()
		m_group_data["path"] = m_path
		# Mock expected
		expected_group_attrs = m_group_data.copy()
		expected_group_attrs[f_auth_field_username] = expected_group_attrs["cn"].lower()
		expected_group_attrs["groupType"] = -LDAPGroupTypes.GROUP_SECURITY.value + LDAPGroupTypes.GROUP_DOMAIN_LOCAL.value
		expected_group_attrs.pop("path", None)
		expected_group_attrs.pop("membersToAdd", None)
		expected_group_attrs.pop("groupScope", None)

		assert f_group_mixin.create_group(
			group_data=m_group_data) == f_group_mixin.ldap_connection
		f_group_mixin.ldap_connection.add.assert_called_once_with(
			dn=f"CN={m_common_name},{m_path}",
			object_class="group",
			attributes=expected_group_attrs
		)
		if not p_group_data.get("membersToAdd", None):
			f_group_mixin.ldap_connection.extend.microsoft.add_members_to_groups.assert_not_called()
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_GROUP,
			log_target=m_common_name,
		)

	def test_create_raises_on_exists(
		mocker: MockerFixture,
		f_group_mixin: GroupViewMixin,
		f_runtime_settings: RuntimeSettingsSingleton
	):
		f_group_mixin.ldap_connection.entries = ["some_entry"]
		f_group_mixin.ldap_filter_attr = "mock_attr_filter"
		f_group_mixin.ldap_filter_object = "mock_obj_filter"
		with pytest.raises(exc_ldap.LDAPObjectExists):
			f_group_mixin.create_group(group_data={"cn":"mock_cn"})
		f_group_mixin.ldap_connection.search.assert_called_once_with(
			search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
			search_filter=f_group_mixin.ldap_filter_object,
			search_scope=SUBTREE,
			attributes=f_group_mixin.ldap_filter_attr,
		)

	def test_create_raises_on_group_create(
		mocker: MockerFixture,
		f_group_mixin: GroupViewMixin,
		f_log_mixin: LogMixin,
		f_logger: Logger,
		f_ldap_search_base: str,
	):
		f_group_mixin.ldap_connection.entries = []
		m_group_data = {
			"cn": "Test Group",
			"path": f"OU=Groups,{f_ldap_search_base}",
			"groupType": 1, # Mapped to Security
			"groupScope": 1, # Mapped to Domain Local
			"membersToAdd": [ "mock_user_dn" ],
		}
		f_group_mixin.ldap_connection.add.side_effect = Exception

		with pytest.raises(exc_groups.GroupCreate):
			f_group_mixin.create_group(
				group_data=m_group_data)
		f_logger.exception.assert_called_once()
		f_group_mixin.ldap_connection.add.assert_called_once()
		f_group_mixin.ldap_connection.extend.microsoft.add_members_to_groups.assert_not_called()
		f_log_mixin.log.assert_not_called()

	def test_create_raises_on_group_member_add(
		mocker: MockerFixture,
		f_group_mixin: GroupViewMixin,
		f_log_mixin: LogMixin,
		f_logger: Logger,
		f_ldap_search_base: str,
	):
		f_group_mixin.ldap_connection.entries = []
		m_group_data = {
			"cn": "Test Group",
			"path": f"OU=Groups,{f_ldap_search_base}",
			"groupType": 1, # Mapped to Security
			"groupScope": 1, # Mapped to Domain Local
			"membersToAdd": [ "mock_user_dn" ],
		}
		f_group_mixin.ldap_connection.extend.microsoft.add_members_to_groups.side_effect = Exception

		with pytest.raises(exc_groups.GroupMembersAdd):
			f_group_mixin.create_group(
				group_data=m_group_data)
		f_logger.exception.assert_called_once()
		f_group_mixin.ldap_connection.add.assert_called_once()
		f_group_mixin.ldap_connection.extend.microsoft.add_members_to_groups.assert_called_once()
		f_log_mixin.log.assert_not_called()
