########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.views.mixins.ldap.group import GroupViewMixin
from core.ldap.types.group import LDAPGroupTypes
from rest_framework.serializers import ValidationError
from core.constants.attrs import (
	LDAP_ATTR_COMMON_NAME,
	LDAP_ATTR_DN,
	LDAP_ATTR_GROUP_TYPE,
	LDAP_ATTR_FIRST_NAME,
	LDAP_ATTR_LAST_NAME,
	LDAP_ATTR_GROUP_MEMBERS,
	LDAP_ATTR_EMAIL,
	LDAP_ATTR_OBJECT_CLASS,
	LDAP_ATTR_OBJECT_CATEGORY,
	LDAP_ATTR_SECURITY_ID,
	LOCAL_ATTR_DN,
	LOCAL_ATTR_NAME,
	LOCAL_ATTR_EMAIL,
	LOCAL_ATTR_GROUP_TYPE,
	LOCAL_ATTR_GROUP_SCOPE,
	LOCAL_ATTR_GROUP_HAS_MEMBERS,
	LOCAL_ATTR_GROUP_MEMBERS,
	LOCAL_ATTR_GROUP_ADD_MEMBERS,
	LOCAL_ATTR_GROUP_RM_MEMBERS,
	LOCAL_ATTR_SECURITY_ID,
	LOCAL_ATTR_PATH,
)
from core.exceptions import (
	ldap as exc_ldap,
	groups as exc_groups,
	dirtree as exc_dirtree,
)
from core.views.mixins.logs import LogMixin
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from tests.test_core.conftest import RuntimeSettingsFactory
from ldap3 import (
	Entry as LDAPEntry,
	SUBTREE,
	Connection,
)
from core.models.application import Application, ApplicationSecurityGroup
from ldap3.utils.dn import safe_rdn
from ldap3.extend import ExtendedOperationsRoot, MicrosoftExtendedOperations
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
from ldap3 import ALL_OPERATIONAL_ATTRIBUTES, ALL_ATTRIBUTES
from typing import Union, Protocol, overload
from logging import Logger

@pytest.fixture
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings("core.views.mixins.ldap.group.RuntimeSettings")


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
def f_distinguished_name(f_runtime_settings: RuntimeSettingsSingleton):
	return f"CN=test,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}"


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
def f_ldap_connector(
	mocker: MockerFixture, f_ldap_connection: MockType
):
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
	return f_runtime_settings.LDAP_FIELD_MAP["username"]


@pytest.fixture
def f_application():
	"""Fixture creating a test application in the database"""
	return Application.objects.create(
		name="Test Application",
		enabled=True,
		client_id="test-client-id",
		client_secret="test-client-secret",
		redirect_uris="http://localhost:8000/callback",
		scopes="openid profile",
	)


@pytest.fixture
def f_application_group(f_application, f_distinguished_name: str):
	"""Fixture creating a test application group in the database"""
	group = ApplicationSecurityGroup.objects.create(
		application=f_application,
		ldap_objects=[f_distinguished_name, "another_group_dn"],
		enabled=True,
	)
	return group


class LDAPGroupEntryFactoryProtocol(Protocol):
	@overload
	def __call__(self, name="testgroup", spec=False, **kwargs) -> LDAPEntry: ...

	def __call__(self, name="testgroup", **kwargs) -> LDAPEntry: ...


@pytest.fixture
def fc_group_entry(
	mocker: MockerFixture, f_ldap_search_base, f_ldap_domain, f_sid_1
):
	def maker(name="testgroup", **kwargs):
		if "spec" in kwargs:
			mock: LDAPEntry = mocker.MagicMock(
				spec=LDAPEntry if kwargs.pop("spec") else None
			)
		else:
			mock: LDAPEntry = mocker.MagicMock()
		mock.entry_attributes = []
		mock.entry_attributes_as_dict = {}
		attrs = {
			LDAP_ATTR_DN: f"CN={name},OU=Groups,{f_ldap_search_base}",
			LDAP_ATTR_GROUP_MEMBERS: [],
			LDAP_ATTR_COMMON_NAME: name,
			LDAP_ATTR_GROUP_TYPE: -LDAPGroupTypes.TYPE_SECURITY.value
			+ LDAPGroupTypes.SCOPE_GLOBAL.value,
			LDAP_ATTR_SECURITY_ID: f_sid_1,
			LDAP_ATTR_EMAIL: f"mock@{f_ldap_domain}",
		} | kwargs
		for k, v in attrs.items():
			m_attr = mocker.Mock()
			m_attr.value = v
			m_attr.values = [v]
			if k == LDAP_ATTR_SECURITY_ID:
				m_attr.raw_values = [v]
			setattr(mock, k, m_attr)
			mock.entry_attributes_as_dict[k] = [v]
			mock.entry_attributes.append(k)
		mock.entry_dn = attrs[LDAP_ATTR_DN]
		return mock

	return maker

class TestGetGroupByRid:
	@staticmethod
	def test_get_group_by_rid_raises_on_none(f_group_mixin: GroupViewMixin):
		with pytest.raises(ValueError, match="rid cannot be None or False"):
			f_group_mixin.get_group_by_rid(rid=None)

	@staticmethod
	def test_get_group_by_rid_raises_on_bad_value(
		f_group_mixin: GroupViewMixin, f_logger: Logger
	):
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
		],
	)
	def test_get_group_by_rid(
		mocker: MockerFixture,
		rid: int,
		should_return_group_entry: bool,
		f_group_mixin: GroupViewMixin,
		fc_group_entry,
		f_ldap_connector: LDAPConnector,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		# Mock result LDAPObject
		m_group_entry = fc_group_entry()
		m_ldap_object = mocker.Mock()
		m_sid = SID(getattr(m_group_entry, LDAP_ATTR_SECURITY_ID))
		m_ldap_object.attributes = {
			LDAP_ATTR_DN: m_group_entry.entry_dn,
			LDAP_ATTR_SECURITY_ID: m_sid,
		}
		mocker.patch(
			"core.views.mixins.ldap.group.LDAPObject",
			return_value=m_ldap_object,
		)
		m_group_without_sid = mocker.MagicMock()
		m_group_without_sid.objectSid = None

		# Mock LDAP Connection
		m_connection = f_ldap_connector.connection
		m_connection.entries = [m_group_entry, m_group_without_sid]
		result = f_group_mixin.get_group_by_rid(rid=rid)
		m_connection.search.assert_any_call(
			search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
			search_filter=LDAPFilter.eq(
				LDAP_ATTR_OBJECT_CLASS,
				"group"
			).to_string(),
			search_scope=SUBTREE,
			attributes=[LDAP_ATTR_SECURITY_ID, LDAP_ATTR_DN],
		)
		if should_return_group_entry:
			m_connection.search.call_count == 2
			m_connection.search.assert_any_call(
				search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
				search_filter=LDAPFilter.eq(
					LDAP_ATTR_DN,
					m_group_entry.entry_dn
				).to_string(),
				search_scope=SUBTREE,
				attributes=ALL_OPERATIONAL_ATTRIBUTES,
			)
			assert isinstance(result, dict)
		else:
			m_connection.search.call_count == 1
			assert result is None


class TestGroupMixinCRUD:
	@staticmethod
	def test_list(
		fc_group_entry: LDAPGroupEntryFactoryProtocol,
		f_group_mixin: GroupViewMixin, 
		f_log_mixin: LogMixin
	):
		f_group_mixin.ldap_filter_attr = [
			LDAP_ATTR_COMMON_NAME,
			LDAP_ATTR_DN,
			LDAP_ATTR_GROUP_TYPE,
			LDAP_ATTR_GROUP_MEMBERS,
		]
		f_group_mixin.ldap_filter_object = LDAPFilter.eq(
			LDAP_ATTR_OBJECT_CLASS, "group"
		)
		m_group_1 = fc_group_entry(
			name="Test Group 1",
			spec=True,
		)
		m_group_2 = fc_group_entry(
			name="Test Group 2",
			spec=True,
			**{
				LDAP_ATTR_GROUP_TYPE: LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value,
				LDAP_ATTR_GROUP_MEMBERS: ["mock_dn"]
			},
		)
		f_group_mixin.ldap_connection.entries = [m_group_1, m_group_2]
		groups, headers = f_group_mixin.list_groups()
		assert headers == (
			LOCAL_ATTR_NAME,
			LOCAL_ATTR_GROUP_TYPE,
			LOCAL_ATTR_GROUP_SCOPE,
			LOCAL_ATTR_GROUP_HAS_MEMBERS,
		)
		assert len(groups) == 2
		assert groups[0].get(LOCAL_ATTR_DN) == m_group_1.entry_dn
		assert groups[1].get(LOCAL_ATTR_DN) == m_group_2.entry_dn
		assert groups[0].get(LOCAL_ATTR_GROUP_HAS_MEMBERS) is False
		assert groups[1].get(LOCAL_ATTR_GROUP_HAS_MEMBERS) is True
		assert groups[0].get(LOCAL_ATTR_GROUP_TYPE) == [
			LDAPGroupTypes.TYPE_SECURITY.name,
		]
		assert groups[0].get(LOCAL_ATTR_GROUP_SCOPE) == [
			LDAPGroupTypes.SCOPE_GLOBAL.name,
		]
		assert groups[1].get(LOCAL_ATTR_GROUP_TYPE) == [
			LDAPGroupTypes.TYPE_DISTRIBUTION.name,
		]
		assert groups[1].get(LOCAL_ATTR_GROUP_SCOPE) == [
			LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name,
		]
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
			name=m_common_name,
			spec=True,
			**{LDAP_ATTR_GROUP_MEMBERS: [m_member_dn]}
		)
		f_group_mixin.ldap_connection.entries = [m_group_entry]
		f_group_mixin.ldap_filter_attr = [
			LDAP_ATTR_COMMON_NAME,
			LDAP_ATTR_EMAIL,
			LDAP_ATTR_GROUP_MEMBERS,
			LDAP_ATTR_DN,
			LDAP_ATTR_GROUP_TYPE,
			LDAP_ATTR_SECURITY_ID,
		]
		f_group_mixin.ldap_filter_object = (
			LDAPFilter.and_(
				LDAPFilter.eq(
					LDAP_ATTR_OBJECT_CLASS,
					"group"
				),
				LDAPFilter.eq(
					LDAP_ATTR_DN,
					m_group_entry
				)
			).to_string()
		)

		# Mock LDAP Object Member
		m_ldap_user_object = mocker.Mock()
		m_ldap_user_attrs = {"attributes": "dict"}
		m_ldap_user_object.attributes = m_ldap_user_attrs
		m_ldap_object = mocker.Mock(return_value=m_ldap_user_object)
		mocker.patch("core.views.mixins.ldap.group.LDAPObject", m_ldap_object)

		group = f_group_mixin.fetch_group()
		f_group_mixin.ldap_connection.search.assert_called_once_with(
			search_base=f_ldap_search_base,
			search_filter=f_group_mixin.ldap_filter_object,
			attributes=f_group_mixin.ldap_filter_attr,
		)
		m_ldap_object.assert_called_once_with(
			connection=f_group_mixin.ldap_connection,
			distinguished_name=m_member_dn,
			search_attrs=[
				LDAP_ATTR_COMMON_NAME,
				LDAP_ATTR_DN,
				f_auth_field_username,
				LDAP_ATTR_FIRST_NAME,
				LDAP_ATTR_LAST_NAME,
				LDAP_ATTR_OBJECT_CATEGORY,
				LDAP_ATTR_OBJECT_CLASS,
			],
		)
		assert isinstance(group, dict)
		assert group.get(LOCAL_ATTR_NAME) == m_common_name
		assert group.get(LOCAL_ATTR_EMAIL) == f"mock@{f_ldap_domain}"
		assert group.get(LOCAL_ATTR_GROUP_MEMBERS) == [m_ldap_user_attrs]
		assert group.get(LOCAL_ATTR_GROUP_TYPE) == [
			LDAPGroupTypes.TYPE_SECURITY.name,
		]
		assert group.get(LOCAL_ATTR_GROUP_SCOPE) == [
			LDAPGroupTypes.SCOPE_GLOBAL.name,
		]
		assert (
			group.get(LOCAL_ATTR_SECURITY_ID)
			== "S-1-5-21-2209570321-9700970-2859064192-1159"
		)
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_READ,
			log_target_class=LOG_CLASS_GROUP,
			log_target=m_common_name,
		)

	@pytest.mark.parametrize(
		"group_data",
		(
			{
				LOCAL_ATTR_NAME: "Test Group",
				LOCAL_ATTR_PATH: None,
				LOCAL_ATTR_GROUP_TYPE: [
					LDAPGroupTypes.TYPE_SECURITY.name
				],
				LOCAL_ATTR_GROUP_SCOPE: [
					LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name
				],
				LOCAL_ATTR_GROUP_ADD_MEMBERS: ["m_user_add"],
				LOCAL_ATTR_GROUP_RM_MEMBERS: ["m_user_rm"],
				LOCAL_ATTR_GROUP_MEMBERS: ["m_user_is_member"],
				LOCAL_ATTR_EMAIL: "test@example.com",
			},
			{
				LOCAL_ATTR_NAME: "Test Group",
				LOCAL_ATTR_GROUP_TYPE: [
					LDAPGroupTypes.TYPE_SECURITY.name
				],
				LOCAL_ATTR_GROUP_SCOPE: [
					LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name
				],
			},
		),
	)
	def test_create(
		self,
		mocker: MockerFixture,
		group_data: dict,
		f_group_mixin: GroupViewMixin,
		f_log_mixin: LogMixin,
		f_ldap_search_base: str,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		# Mock Class
		m_ldap_group_instance = mocker.Mock()
		MockLDAPGroup = mocker.patch(
			"core.views.mixins.ldap.group.LDAPGroup",
			return_value=m_ldap_group_instance
		)

		f_group_mixin.ldap_connection.entries = []
		m_common_name = group_data[LOCAL_ATTR_NAME]
		if LOCAL_ATTR_PATH in group_data:
			m_path = f"OU=Groups,{f_ldap_search_base}"
			expected_dn = "CN=%s,%s" % (group_data[LOCAL_ATTR_NAME], m_path)
			group_data[LOCAL_ATTR_PATH] = m_path
		else:
			expected_dn = "CN=%s,CN=Users,%s" % (
				group_data[LOCAL_ATTR_NAME],
				f_runtime_settings.LDAP_AUTH_SEARCH_BASE
			)

		assert (
			f_group_mixin.create_group(group_data=group_data)
			== f_group_mixin.ldap_connection
		)
		MockLDAPGroup.assert_called_once_with(
			connection=f_group_mixin.ldap_connection,
			attributes=group_data,
			distinguished_name=expected_dn,
		)
		m_ldap_group_instance.save.assert_called_once()
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_CREATE,
			log_target_class=LOG_CLASS_GROUP,
			log_target=m_common_name,
		)

	def test_create_raises_group_cn_falsy(
		mocker: MockerFixture,
		f_group_mixin: GroupViewMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_group_mixin.ldap_connection.entries = ["some_entry_with_same_dn"]
		f_group_mixin.ldap_filter_attr = "mock_attr_filter"
		f_group_mixin.ldap_filter_object = "mock_obj_filter"
		with pytest.raises(ValueError, match="cannot be None or falsy"):
			f_group_mixin.create_group(
				group_data={LOCAL_ATTR_NAME: ""}
			)
		f_group_mixin.ldap_connection.search.assert_not_called()

	def test_create_raises_on_exists(
		mocker: MockerFixture,
		f_group_mixin: GroupViewMixin,
		f_runtime_settings: RuntimeSettingsSingleton,
	):
		f_group_mixin.ldap_connection.entries = ["some_entry_with_same_dn"]
		f_group_mixin.ldap_filter_attr = "mock_attr_filter"
		f_group_mixin.ldap_filter_object = "mock_obj_filter"
		with pytest.raises(exc_ldap.LDAPObjectExists):
			f_group_mixin.create_group(
				group_data={LOCAL_ATTR_NAME: "mock_cn"}
			)
		f_group_mixin.ldap_connection.search.assert_called_once_with(
			search_base=f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
			search_filter=f_group_mixin.ldap_filter_object,
			search_scope=SUBTREE,
			attributes=f_group_mixin.ldap_filter_attr,
		)

	def test_update(
		self,
		mocker: MockerFixture,
		f_group_mixin: GroupViewMixin,
		f_log_mixin: LogMixin,
		f_distinguished_name: str,
	):
		# Mocks
		mock_data = {
			LOCAL_ATTR_DN: f_distinguished_name,
			LOCAL_ATTR_EMAIL: "test@example.com",
		}
		f_group_mixin.ldap_filter_attr = "search_attrs"

		# Mock LDAPGroup Class
		m_ldap_group_instance = mocker.Mock()
		m_ldap_group_instance.exists = True
		m_ldap_group_instance.attributes = mock_data
		m_get_common_name = mocker.Mock(
			name="m_get_common_name", return_value="test")
		m_ldap_group_instance.__get_common_name__ = m_get_common_name
		MockLDAPGroup = mocker.patch(
			"core.views.mixins.ldap.group.LDAPGroup",
			return_value=m_ldap_group_instance
		)

		assert (
			f_group_mixin.update_group(data=mock_data)
			== f_group_mixin.ldap_connection
		)
		MockLDAPGroup.assert_called_once_with(
			connection=f_group_mixin.ldap_connection,
			distinguished_name=f_distinguished_name,
			search_attrs=f_group_mixin.ldap_filter_attr,
		)
		assert m_ldap_group_instance.attributes == mock_data
		m_ldap_group_instance.save.assert_called_once()
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_GROUP,
			log_target="test",
		)

	def test_update_raises_system_flag_deleted(
		self,
		mocker: MockerFixture,
		f_group_mixin: GroupViewMixin,
		f_log_mixin: LogMixin,
		f_distinguished_name: str,
	):
		# Mocks
		mock_data = {
			LOCAL_ATTR_DN: f_distinguished_name,
			LOCAL_ATTR_EMAIL: "test@example.com",
			LOCAL_ATTR_GROUP_TYPE: [LDAPGroupTypes.TYPE_SECURITY.name]
		}
		f_group_mixin.ldap_filter_attr = "search_attrs"

		# Mock LDAPGroup Class
		m_ldap_group_instance = mocker.Mock()
		m_ldap_group_instance.exists = True
		old_data = mock_data.copy()
		old_data[LOCAL_ATTR_GROUP_TYPE] = [
			LDAPGroupTypes.TYPE_SECURITY.name,
			LDAPGroupTypes.TYPE_SYSTEM.name,
		]
		m_ldap_group_instance.attributes = old_data
		m_get_common_name = mocker.Mock(
			name="m_get_common_name", return_value="test")
		m_ldap_group_instance.__get_common_name__ = m_get_common_name
		MockLDAPGroup = mocker.patch(
			"core.views.mixins.ldap.group.LDAPGroup",
			return_value=m_ldap_group_instance
		)

		with pytest.raises(ValidationError) as exc:
			f_group_mixin.update_group(data=mock_data)
		assert "cannot have its SYSTEM" in exc.value.args[0].get(
			LOCAL_ATTR_GROUP_TYPE
		)
		MockLDAPGroup.assert_called_once_with(
			connection=f_group_mixin.ldap_connection,
			distinguished_name=f_distinguished_name,
			search_attrs=f_group_mixin.ldap_filter_attr,
		)
		m_ldap_group_instance.save.assert_not_called()
		m_get_common_name.assert_not_called()
		f_log_mixin.log.assert_not_called()

	@staticmethod
	def test_update_raises_no_dn(f_group_mixin: GroupViewMixin):
		with pytest.raises(exc_groups.GroupDistinguishedNameMissing):
			f_group_mixin.update_group(data={LOCAL_ATTR_DN: None})

	@staticmethod
	def test_update_raises_group_does_not_exist(
		mocker: MockerFixture,
		f_group_mixin: GroupViewMixin,
		f_distinguished_name: str,
	):
		# Mock Class
		m_ldap_group_instance = mocker.Mock()
		m_ldap_group_instance.exists = False
		mocker.patch(
			"core.views.mixins.ldap.group.LDAPGroup",
			return_value=m_ldap_group_instance
		)
		with pytest.raises(exc_groups.GroupDoesNotExist):
			f_group_mixin.update_group(
				data={LOCAL_ATTR_DN: f_distinguished_name}
			)

	@staticmethod
	def test_delete_raises_no_dn(f_group_mixin: GroupViewMixin):
		with pytest.raises(exc_ldap.DistinguishedNameValidationError):
			f_group_mixin.delete_group(group_data={})

	@staticmethod
	def test_delete_raises_cn_not_in_dn(
		mocker: MockerFixture,
		f_group_mixin: GroupViewMixin,
		f_distinguished_name: str,
	):
		m_group_entry = mocker.Mock()
		m_group_entry.attributes = {LDAP_ATTR_COMMON_NAME: "CN=Bad"}
		# Mock old Group LDAP Entry
		mocker.patch(
			"core.views.mixins.ldap.group.LDAPObject",
			return_value=m_group_entry,
		)
		with pytest.raises(exc_ldap.DistinguishedNameValidationError):
			f_group_mixin.delete_group(
				group_data={LDAP_ATTR_DN: f_distinguished_name}
			)

	@staticmethod
	def test_delete_group_not_exists(
		mocker: MockerFixture,
		f_group_mixin: GroupViewMixin,
		f_distinguished_name: str,
	):
		# Mock LDAPGroup Class
		m_ldap_group_instance = mocker.Mock()
		m_ldap_group_instance.exists = False
		mocker.patch(
			"core.views.mixins.ldap.group.LDAPGroup",
			return_value=m_ldap_group_instance
		)

		with pytest.raises(exc_groups.GroupDoesNotExist):
			f_group_mixin.delete_group(
				group_data={LOCAL_ATTR_DN: f_distinguished_name}
			)

	@staticmethod
	@pytest.mark.django_db
	def test_delete(
		mocker: MockerFixture,
		f_distinguished_name: str,
		f_group_mixin: GroupViewMixin,
		f_log_mixin: LogMixin,
		f_application_group: ApplicationSecurityGroup,
	):
		# Mock LDAPGroup Class
		m_ldap_group_instance = mocker.Mock()
		m_ldap_group_instance.exists = True
		m_ldap_group_instance.attributes = {
			LOCAL_ATTR_GROUP_TYPE: [LDAPGroupTypes.TYPE_SECURITY.name]
		}
		m_get_common_name = mocker.Mock(
			name="m_get_common_name", return_value="test")
		m_ldap_group_instance.__get_common_name__ = m_get_common_name
		MockLDAPGroup = mocker.patch(
			"core.views.mixins.ldap.group.LDAPGroup",
			return_value=m_ldap_group_instance
		)

		f_group_mixin.delete_group(
			group_data={LOCAL_ATTR_DN: f_distinguished_name}
		)

		MockLDAPGroup.assert_called_once_with(
			connection=f_group_mixin.ldap_connection,
			distinguished_name=f_distinguished_name,
			search_attrs=f_group_mixin.ldap_filter_attr,
		)
		m_ldap_group_instance.delete.assert_called_once()
		f_log_mixin.log.assert_called_once_with(
			user=1,
			operation_type=LOG_ACTION_DELETE,
			log_target_class=LOG_CLASS_GROUP,
			log_target="test",
		)
		# Check that DN has been removed from ASG
		f_application_group.refresh_from_db()
		assert f_application_group.ldap_objects == ["another_group_dn"]

	@staticmethod
	@pytest.mark.django_db
	def test_delete_raises_builtin_protect(
		mocker: MockerFixture,
		f_distinguished_name: str,
		f_group_mixin: GroupViewMixin,
		f_log_mixin: LogMixin,
		f_application_group: ApplicationSecurityGroup,
	):
		# Mock LDAPGroup Class
		m_ldap_group_instance = mocker.Mock()
		m_ldap_group_instance.exists = True
		m_ldap_group_instance.attributes = {
			LOCAL_ATTR_GROUP_TYPE: [
				LDAPGroupTypes.TYPE_SECURITY.name,
				LDAPGroupTypes.TYPE_SYSTEM.name,
			]
		}
		m_get_common_name = mocker.Mock(
			name="m_get_common_name", return_value="test")
		m_ldap_group_instance.__get_common_name__ = m_get_common_name
		mocker.patch(
			"core.views.mixins.ldap.group.LDAPGroup",
			return_value=m_ldap_group_instance
		)

		with pytest.raises(exc_groups.GroupBuiltinProtect):
			f_group_mixin.delete_group(
				group_data={LOCAL_ATTR_DN: f_distinguished_name}
			)
		m_ldap_group_instance.delete.assert_not_called()
		f_log_mixin.log.assert_not_called()
		# Check that DN has not been removed from ASG
		f_application_group.refresh_from_db()
		assert f_application_group.ldap_objects == [
			f_distinguished_name,
			"another_group_dn"
		]
