########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.models.ldap_object import LDAPObject
from core.models.ldap_group import LDAPGroup, DEFAULT_LOCAL_ATTRS
from .test_ldap_object import TestDunderValidateInit as SuperDunderValidateInit
from core.type_hints.connector import LDAPConnectionProtocol
from core.ldap.types.group import LDAPGroupTypes
from core.constants.attrs import *
from core.ldap.filter import LDAPFilter, LDAPFilterType
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from core.views.mixins.ldap.organizational_unit import OrganizationalUnitMixin
from core.exceptions import (
	ldap as exc_ldap,
	groups as exc_group,
)
from tests.test_core.conftest import (
	LDAPAttributeFactoryProtocol,
	LDAPEntryFactoryProtocol,
	RuntimeSettingsFactory,
)


class TestInit:
	def test_success(
		self, mocker: MockerFixture, g_runtime_settings: RuntimeSettingsFactory
	):
		m_runtime_settings = g_runtime_settings(
			patch_path="core.models.ldap_user.RuntimeSettings"
		)
		m_super_init = mocker.patch.object(LDAPObject, "__init__")
		m_ldap_group = LDAPGroup(some_kwarg=True)
		m_super_init.assert_called_once_with(some_kwarg=True)
		assert m_ldap_group.search_attrs == {
			m_runtime_settings.LDAP_FIELD_MAP.get(attr)
			for attr in DEFAULT_LOCAL_ATTRS
			if m_runtime_settings.LDAP_FIELD_MAP.get(attr, None)
		}


class TestDunderValidateInit(SuperDunderValidateInit):
	test_cls = LDAPGroup

	def test_only_with_common_name(self, mocker: MockerFixture):
		mocker.patch.object(self.test_cls, "__init__", return_value=None)
		m_ldap_group = self.test_cls()
		m_ldap_group.__validate_init__(**{LOCAL_ATTR_NAME: "Test Group"})
		result_filter = LDAPFilter.from_string(m_ldap_group.search_filter)
		assert result_filter.children[1].type == LDAPFilterType.EQUALITY
		assert result_filter.children[1].attribute == LDAP_ATTR_COMMON_NAME
		assert result_filter.children[1].value == "Test Group"


def parse_read_group_type_scope_ids(v):
	if isinstance(v, list):
		return ",".join(v)


class TestParseReadGroupTypeScope:
	@pytest.mark.parametrize(
		"v, expected_types, expected_scopes",
		(
			### SECURITY TYPE
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value
					+ LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_SECURITY.name],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value
					+ LDAPGroupTypes.SCOPE_UNIVERSAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_SECURITY.name],
				[LDAPGroupTypes.SCOPE_UNIVERSAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value
					+ LDAPGroupTypes.SCOPE_GLOBAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_SECURITY.name],
				[LDAPGroupTypes.SCOPE_GLOBAL.name],
			),
			### DISTRIBUTION TYPE
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value
					+ LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_DISTRIBUTION.name],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value
					+ LDAPGroupTypes.SCOPE_UNIVERSAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_DISTRIBUTION.name],
				[LDAPGroupTypes.SCOPE_UNIVERSAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value
					+ LDAPGroupTypes.SCOPE_GLOBAL.value
				),
				# Expected results
				[LDAPGroupTypes.TYPE_DISTRIBUTION.name],
				[LDAPGroupTypes.SCOPE_GLOBAL.name],
			),
			### SECURITY TYPE WITH SYSTEM FLAG
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value
					+ LDAPGroupTypes.TYPE_SYSTEM.value
					+ LDAPGroupTypes.SCOPE_GLOBAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_SECURITY.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_GLOBAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value
					+ LDAPGroupTypes.TYPE_SYSTEM.value
					+ LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_SECURITY.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_SECURITY.value
					+ LDAPGroupTypes.TYPE_SYSTEM.value
					+ LDAPGroupTypes.SCOPE_UNIVERSAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_SECURITY.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_UNIVERSAL.name],
			),
			### DISTRIBUTION TYPE WITH SYSTEM FLAG
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value
					+ LDAPGroupTypes.TYPE_SYSTEM.value
					+ LDAPGroupTypes.SCOPE_GLOBAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_DISTRIBUTION.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_GLOBAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value
					+ LDAPGroupTypes.TYPE_SYSTEM.value
					+ LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_DISTRIBUTION.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
			),
			pytest.param(
				# Int to parse
				(
					-LDAPGroupTypes.TYPE_DISTRIBUTION.value
					+ LDAPGroupTypes.TYPE_SYSTEM.value
					+ LDAPGroupTypes.SCOPE_UNIVERSAL.value
				),
				# Expected results
				[
					LDAPGroupTypes.TYPE_DISTRIBUTION.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_UNIVERSAL.name],
			),
		),
		ids=parse_read_group_type_scope_ids,
	)
	def test_success(
		self, mocker: MockerFixture, v, expected_types, expected_scopes
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_group = LDAPGroup()
		group_types, group_scopes = m_ldap_group.parse_read_group_type_scope(v)
		assert group_types == expected_types
		assert group_scopes == expected_scopes

	def test_success_from_str(self, mocker: MockerFixture):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_group = LDAPGroup()
		group_types, group_scopes = m_ldap_group.parse_read_group_type_scope(
			str(
				LDAPGroupTypes.TYPE_DISTRIBUTION.value
				+ LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
			)
		)
		assert group_types == [LDAPGroupTypes.TYPE_DISTRIBUTION.name]
		assert group_scopes == [LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name]

	def test_raises_from_str(self, mocker: MockerFixture):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_group = LDAPGroup()
		with pytest.raises(ValueError, match="could not be cast"):
			m_ldap_group.parse_read_group_type_scope("some_str")

	@pytest.mark.parametrize(
		"bad_value",
		(
			b"some_bytes",
			False,
			None,
			True,
		),
	)
	def test_raises_type_error(self, mocker: MockerFixture, bad_value):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_group = LDAPGroup()
		with pytest.raises(TypeError, match="must be of type"):
			m_ldap_group.parse_read_group_type_scope(bad_value)

	def test_raises_from_invalid_int(self, mocker: MockerFixture):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_group = LDAPGroup()
		with pytest.raises(ValueError, match="group type integer calculation"):
			m_ldap_group.parse_read_group_type_scope(1234)


class TestParseWriteGroupTypeScope:
	@pytest.mark.parametrize(
		"m_types, m_scopes, expected",
		(
			(
				[LDAPGroupTypes.TYPE_SECURITY.name],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
				(
					-LDAPGroupTypes.TYPE_SECURITY.value
					+ LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
			),
			(
				[LDAPGroupTypes.TYPE_DISTRIBUTION.name],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
				(
					LDAPGroupTypes.TYPE_DISTRIBUTION.value
					+ LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
			),
			(
				[
					LDAPGroupTypes.TYPE_SECURITY.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
				(
					-LDAPGroupTypes.TYPE_SECURITY.value
					+ LDAPGroupTypes.TYPE_SYSTEM.value
					+ LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
			),
			(
				[
					LDAPGroupTypes.TYPE_DISTRIBUTION.name,
					LDAPGroupTypes.TYPE_SYSTEM.name,
				],
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
				(
					LDAPGroupTypes.TYPE_DISTRIBUTION.value
					+ LDAPGroupTypes.TYPE_SYSTEM.value
					+ LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
				),
			),
		),
	)
	def test_success(
		self,
		m_types: list[LDAPGroupTypes],
		m_scopes: list[LDAPGroupTypes],
		expected: int,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_parse_read = mocker.patch.object(
			LDAPGroup,
			"parse_read_group_type_scope",
			return_value=(
				m_types,
				m_scopes,
			),
		)
		m_ldap_group = LDAPGroup()
		m_ldap_group.parsed_specials = []
		m_ldap_group.attributes = {
			LOCAL_ATTR_GROUP_TYPE: m_types,
			LOCAL_ATTR_GROUP_SCOPE: m_scopes,
		}
		m_ldap_group.parse_write_group_type_scope()
		m_parse_read.assert_called_once_with(expected)
		assert set(m_ldap_group.parsed_specials) == {LOCAL_ATTR_GROUP_TYPE}
		assert m_ldap_group.attributes.get(LOCAL_ATTR_GROUP_TYPE) == expected

	@pytest.mark.parametrize(
		"m_types, m_scopes",
		(
			(
				[LDAPGroupTypes.TYPE_SECURITY.name],
				None,
			),
			(
				None,
				[LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.name],
			),
			(
				None,
				None,
			),
		),
	)
	def test_does_not_parse_on_missing_value(
		self,
		m_types,
		m_scopes,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_parse_read = mocker.patch.object(
			LDAPGroup, "parse_read_group_type_scope"
		)
		m_ldap_group = LDAPGroup()
		m_ldap_group.parsed_specials = []
		m_ldap_group.attributes = {}
		if m_types:
			m_ldap_group.attributes[LOCAL_ATTR_GROUP_TYPE] = m_types
		if m_scopes:
			m_ldap_group.attributes[LOCAL_ATTR_GROUP_SCOPE] = m_scopes
		m_ldap_group.parse_write_group_type_scope()
		m_parse_read.assert_not_called()
		assert m_ldap_group.parsed_specials == []
		assert LOCAL_ATTR_GROUP_TYPE not in m_ldap_group.attributes


class TestParseWriteCommonName:
	@pytest.mark.parametrize(
		"m_name",
		(
			"New Name",
			"CN=New Name",
		),
	)
	def test_success_rename(
		self,
		m_name: str,
		f_runtime_settings: RuntimeSettingsSingleton,
		mocker: MockerFixture,
	):
		m_new_dn = "CN=%s,%s" % (
			m_name,
			f_runtime_settings.LDAP_AUTH_SEARCH_BASE,
		)
		m_old_dn = "CN=Original Name,%s" % (
			f_runtime_settings.LDAP_AUTH_SEARCH_BASE
		)
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_move_or_rename = mocker.patch.object(
			OrganizationalUnitMixin,
			"move_or_rename_object",
			return_value=m_new_dn,
		)
		m_ldap_group = LDAPGroup()
		m_request = mocker.Mock()
		m_ldap_group.context = {"request": m_request}
		m_ldap_group.distinguished_name = m_old_dn
		m_ldap_group.attributes = {
			LOCAL_ATTR_NAME: m_name,
		}

		m_ldap_group.parse_write_common_name()
		m_move_or_rename.assert_called_once_with(
			m_ldap_group,
			distinguished_name=m_old_dn,
			target_rdn=m_name,
			responsible_user=m_request.user,
		)
		assert m_ldap_group.distinguished_name == m_new_dn

	def test_raises_bad_cn_parts(
		self,
		f_runtime_settings: RuntimeSettingsSingleton,
		mocker: MockerFixture,
	):
		m_name = "CN=cn=pepe"
		m_old_dn = "CN=Original Name,%s" % (
			f_runtime_settings.LDAP_AUTH_SEARCH_BASE
		)
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_move_or_rename = mocker.patch.object(
			OrganizationalUnitMixin, "move_or_rename_object"
		)
		m_ldap_group = LDAPGroup()
		m_ldap_group.distinguished_name = m_old_dn
		m_ldap_group.attributes = {
			LOCAL_ATTR_NAME: m_name,
		}

		with pytest.raises(exc_ldap.DistinguishedNameValidationError):
			m_ldap_group.parse_write_common_name()
		m_move_or_rename.assert_not_called()
		assert m_ldap_group.distinguished_name == m_old_dn


class TestPerformMemberOperations:
	def test_success(
		self,
		mocker: MockerFixture,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
		f_connection: LDAPConnectionProtocol,
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_add_members = ["mock_member_1", "mock_member_2"]
		m_rm_members = ["mock_member_3", "mock_member_4"]

		m_ldap_group = LDAPGroup()
		m_ldap_group.entry = fc_ldap_entry(
			spec=False,
			**{LDAP_ATTR_GROUP_MEMBERS: ["mock_member_1", "mock_member_3"]},
		)
		m_ldap_group.connection = f_connection
		m_ldap_group.distinguished_name = "mock_dn"
		m_ldap_group.parsed_specials = []

		m_ldap_group.perform_member_operations(
			members_to_add=m_add_members,
			members_to_remove=m_rm_members,
		)
		f_connection.extend.microsoft.add_members_to_groups.assert_called_once_with(
			members={"mock_member_2"},
			groups="mock_dn",
		)
		f_connection.extend.microsoft.remove_members_from_groups.assert_called_once_with(
			members={"mock_member_3"},
			groups="mock_dn",
		)
		assert set(m_ldap_group.parsed_specials) == {
			LOCAL_ATTR_GROUP_ADD_MEMBERS,
			LOCAL_ATTR_GROUP_RM_MEMBERS,
		}

	def test_logs_and_returns_none(
		self, mocker: MockerFixture, fc_ldap_attr: LDAPAttributeFactoryProtocol
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_group = LDAPGroup()
		m_ldap_group.entry = mocker.Mock()
		delattr(m_ldap_group.entry, LDAP_ATTR_GROUP_MEMBERS)
		assert m_ldap_group.perform_member_operations() is None

	def test_add_members_raises(
		self,
		mocker: MockerFixture,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
		f_connection: LDAPConnectionProtocol,
	):
		m_logger = mocker.patch("core.models.ldap_group.logger")
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		f_connection.extend.microsoft.add_members_to_groups.side_effect = (
			Exception
		)
		f_connection.result = "bad_result"
		m_add_members = ["mock_member_1", "mock_member_2"]
		m_rm_members = ["mock_member_3", "mock_member_4"]

		m_ldap_group = LDAPGroup()
		m_ldap_group.entry = fc_ldap_entry(
			spec=False, **{LDAP_ATTR_GROUP_MEMBERS: []}
		)
		m_ldap_group.connection = f_connection
		m_ldap_group.distinguished_name = "mock_dn"
		m_ldap_group.parsed_specials = []

		with pytest.raises(exc_group.GroupMembersAdd):
			m_ldap_group.perform_member_operations(
				members_to_add=m_add_members,
				members_to_remove=m_rm_members,
			)
		m_logger.exception.assert_called_once()
		f_connection.extend.microsoft.add_members_to_groups.assert_called_once_with(
			members=set(m_add_members),
			groups="mock_dn",
		)
		f_connection.extend.microsoft.remove_members_from_groups.assert_not_called()
		assert not m_ldap_group.parsed_specials

	def test_remove_members_raises(
		self,
		mocker: MockerFixture,
		fc_ldap_entry: LDAPEntryFactoryProtocol,
		f_connection: LDAPConnectionProtocol,
	):
		m_logger = mocker.patch("core.models.ldap_group.logger")
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		f_connection.extend.microsoft.remove_members_from_groups.side_effect = (
			Exception
		)
		f_connection.result = "bad_result"
		m_add_members = ["mock_member_1", "mock_member_2"]
		m_rm_members = ["mock_member_3", "mock_member_4"]

		m_ldap_group = LDAPGroup()
		m_ldap_group.entry = fc_ldap_entry(
			spec=False, **{LDAP_ATTR_GROUP_MEMBERS: m_rm_members}
		)
		m_ldap_group.connection = f_connection
		m_ldap_group.distinguished_name = "mock_dn"
		m_ldap_group.parsed_specials = []

		with pytest.raises(exc_group.GroupMembersRemove):
			m_ldap_group.perform_member_operations(
				members_to_add=m_add_members,
				members_to_remove=m_rm_members,
			)
		m_logger.exception.assert_called_once()
		f_connection.extend.microsoft.add_members_to_groups.assert_called_once_with(
			members=set(m_add_members),
			groups="mock_dn",
		)
		f_connection.extend.microsoft.remove_members_from_groups.assert_called_once_with(
			members=set(m_rm_members),
			groups="mock_dn",
		)
		assert set(m_ldap_group.parsed_specials) == {
			LOCAL_ATTR_GROUP_ADD_MEMBERS
		}


class TestParseWriteSpecialAttributes:
	def test_success(
		self,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_parse_write_group_ts = mocker.patch.object(
			LDAPGroup, "parse_write_group_type_scope"
		)
		m_ldap_group = LDAPGroup()
		m_ldap_group.parse_write_special_attributes()
		m_parse_write_group_ts.assert_called_once()


class TestParseReadSpecialAttributes:
	def test_success(
		self,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_parse_read_group_ts = mocker.patch.object(
			LDAPGroup,
			"parse_read_group_type_scope",
			return_value=(
				"m_types",
				"m_scopes",
			),
		)
		m_group_type = (
			-LDAPGroupTypes.TYPE_SECURITY.value
			+ LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value
		)
		m_attr = mocker.Mock(name="m_group_type")
		m_attr.value = m_group_type
		m_entry = mocker.Mock()
		m_entry.entry_attributes = [LDAP_ATTR_GROUP_TYPE]
		setattr(m_entry, LDAP_ATTR_GROUP_TYPE, m_attr)
		m_ldap_group = LDAPGroup()
		m_ldap_group.attributes = {}
		m_ldap_group.entry = m_entry

		m_ldap_group.parse_read_special_attributes()
		m_parse_read_group_ts.assert_called_once_with(m_group_type)


class TestPostCreate:
	def test_success(
		self,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_perform_member_operations = mocker.patch.object(
			LDAPGroup, "perform_member_operations", return_value=None
		)
		m_ldap_group = LDAPGroup()
		m_ldap_group.attributes = {
			LOCAL_ATTR_GROUP_ADD_MEMBERS: ["mock_add"],
			LOCAL_ATTR_GROUP_RM_MEMBERS: ["mock_rm"],
		}
		m_ldap_group.post_create()
		m_perform_member_operations.assert_called_once_with(
			members_to_add=["mock_add"],
			members_to_remove=["mock_rm"],
		)

	def test_success_no_operations(
		self,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_perform_member_operations = mocker.patch.object(
			LDAPGroup, "perform_member_operations", return_value=None
		)
		m_ldap_group = LDAPGroup()
		m_ldap_group.attributes = {}
		m_ldap_group.post_create()
		m_perform_member_operations.assert_called_once_with(
			members_to_add=[],
			members_to_remove=[],
		)


class TestPostUpdate:
	def test_success(
		self,
		mocker: MockerFixture,
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_group = LDAPGroup()
		m_post_create = mocker.patch.object(
			LDAPGroup, "post_create", return_value=None
		)
		m_parse_write_common_name = mocker.patch.object(
			LDAPGroup, "parse_write_common_name", return_value=None
		)
		m_ldap_group.post_update()
		m_post_create.assert_called_once()
		m_parse_write_common_name.assert_called_once()


class TestSave:
	@pytest.mark.parametrize(
		"add_members, rm_members, expected_force_post_update",
		(
			([], [], False),
			([], ["mock_member"], True),
			(["mock_member"], [], True),
		),
	)
	def test_success(
		self,
		mocker: MockerFixture,
		add_members,
		rm_members,
		expected_force_post_update,
	):
		mocker.patch.object(LDAPGroup, "__init__", return_value=None)
		m_ldap_group = LDAPGroup()
		m_ldap_group.attributes = {
			LOCAL_ATTR_GROUP_ADD_MEMBERS: add_members,
			LOCAL_ATTR_GROUP_RM_MEMBERS: rm_members,
		}
		m_save = mocker.patch.object(LDAPObject, "save")
		m_ldap_group.save()
		m_save.assert_called_once_with(
			update_kwargs={"force_post_update": expected_force_post_update}
		)
