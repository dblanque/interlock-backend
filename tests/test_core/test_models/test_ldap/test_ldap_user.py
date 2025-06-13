########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture, MockType

################################################################################
from core.models.ldap_user import LDAPUser
from core.constants.attrs import *
from core.ldap.filter import LDAPFilter, LDAPFilterType
from .test_ldap_object import TestDunderValidateInit as SuperDunderValidateInit
from core.type_hints.connector import LDAPConnectionProtocol
from core.exceptions import users as exc_user, base as exc_base
from typing import Protocol
from core.ldap.adsi import (
	calc_permissions,
	LDAP_PERMS,
	LDAP_UF_ACCOUNT_DISABLE,
	LDAP_UF_NORMAL_ACCOUNT,
	LDAP_UF_DONT_EXPIRE_PASSWD,
	LDAP_UF_PASSWD_CANT_CHANGE,
)


class InitlessLDAPUserFactory(Protocol):
	def __call__(self, **kwargs) -> LDAPUser: ...


@pytest.fixture
def f_ldap_user_no_init(mocker: MockerFixture) -> InitlessLDAPUserFactory:
	def maker(**kwargs):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = LDAPUser()
		for kw, val in kwargs.items():
			setattr(m_ldap_user, kw, val)
		return m_ldap_user

	return maker


class TestDunderValidateInit(SuperDunderValidateInit):
	test_cls = LDAPUser

	def test_only_with_username(self, mocker: MockerFixture):
		mocker.patch.object(self.test_cls, "__init__", return_value=None)
		m_ldap_user = self.test_cls()
		m_ldap_user.__validate_init__(**{LOCAL_ATTR_USERNAME: "testuser"})
		result_filter = LDAPFilter.from_string(m_ldap_user.search_filter)
		assert result_filter.children[1].type == LDAPFilterType.EQUALITY
		assert (
			result_filter.children[1].attribute == LDAP_ATTR_USERNAME_SAMBA_ADDS
		)
		assert result_filter.children[1].value == "testuser"


class TestParseWriteSpecialAttributes:
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		m_ldap_user = f_ldap_user_no_init(
			**{
				"attributes": {
					LOCAL_ATTR_USER_GROUPS: ["group_a", "group_b"],
					LOCAL_ATTR_USER_RM_GROUPS: ["group_b_dn"],
					LOCAL_ATTR_COUNTRY: "some_country",
					LOCAL_ATTR_PERMISSIONS: ["some_permissions"],
				}
			}
		)
		m_parse_add_groups = mocker.patch.object(
			LDAPUser, "parse_add_groups"
		)
		m_parse_remove_groups = mocker.patch.object(
			LDAPUser, "parse_remove_groups"
		)
		m_parse_write_country = mocker.patch.object(
			LDAPUser, "parse_write_country"
		)
		m_parse_write_permissions = mocker.patch.object(
			LDAPUser, "parse_write_permissions"
		)
		m_ldap_user.parse_write_special_attributes()
		m_parse_add_groups.assert_called_once()
		m_parse_remove_groups.assert_called_once_with(
			groups=["group_a", "group_b"],
			remove_group_dns=["group_b_dn"],
		)
		m_parse_write_country.assert_called_once_with("some_country")
		m_parse_write_permissions.assert_called_once_with(["some_permissions"])


class TestPostCreate:
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			**{
				"attributes": {
					LOCAL_ATTR_USER_ADD_GROUPS: ["mock_group_1"],
					LOCAL_ATTR_USER_RM_GROUPS: ["mock_group_2"],
				}
			}
		)
		m_perform_group_ops = mocker.patch.object(
			LDAPUser, "perform_group_operations"
		)
		m_ldap_user.post_create()
		m_perform_group_ops.assert_called_once_with(
			groups_to_add=m_ldap_user.attributes.get(
				LOCAL_ATTR_USER_ADD_GROUPS, []
			),
			groups_to_remove=m_ldap_user.attributes.get(
				LOCAL_ATTR_USER_RM_GROUPS, []
			),
		)


class TestPostUpdate:
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init()
		m_post_create = mocker.patch.object(LDAPUser, "post_create")

		m_ldap_user.post_update()
		m_post_create.assert_called_once()


class TestParseWriteCountry:
	def test_success(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			attributes={
				LOCAL_ATTR_COUNTRY: "Argentina",
			},
			parsed_specials=[],
		)

		m_ldap_user.parse_write_country(
			m_ldap_user.attributes[LOCAL_ATTR_COUNTRY]
		)
		assert set(m_ldap_user.parsed_specials) == set(
			[LOCAL_ATTR_COUNTRY, LOCAL_ATTR_COUNTRY_DCC, LOCAL_ATTR_COUNTRY_ISO]
		)
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY] == "Argentina"
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY_DCC] == 32
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY_ISO] == "AR"

	@pytest.mark.parametrize(
		"value",
		(
			"",
			None,
		),
	)
	def test_success_no_value(
		self,
		value,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			attributes={
				LOCAL_ATTR_COUNTRY: value,
			},
			parsed_specials=[],
		)

		m_ldap_user.parse_write_country(
			m_ldap_user.attributes[LOCAL_ATTR_COUNTRY]
		)
		assert set(m_ldap_user.parsed_specials) == set(
			[LOCAL_ATTR_COUNTRY, LOCAL_ATTR_COUNTRY_DCC, LOCAL_ATTR_COUNTRY_ISO]
		)
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY] == None
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY_DCC] == 0
		assert m_ldap_user.attributes[LOCAL_ATTR_COUNTRY_ISO] == None


class TestParseWritePermissions:
	@pytest.mark.parametrize(
		"permissions, expected",
		(
			(None, None),
			([], LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"]),
			(
				[LDAP_UF_NORMAL_ACCOUNT],
				LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"],
			),
			(
				[
					LDAP_UF_NORMAL_ACCOUNT,
					LDAP_UF_ACCOUNT_DISABLE,
					LDAP_UF_DONT_EXPIRE_PASSWD,
				],
				LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"]
				+ LDAP_PERMS[LDAP_UF_ACCOUNT_DISABLE]["value"]
				+ LDAP_PERMS[LDAP_UF_DONT_EXPIRE_PASSWD]["value"],
			),
			(
				[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_ACCOUNT_DISABLE],
				LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"]
				+ LDAP_PERMS[LDAP_UF_ACCOUNT_DISABLE]["value"],
			),
		),
	)
	def test_success(
		self,
		permissions: list[str],
		expected: int,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			attributes={
				LOCAL_ATTR_PERMISSIONS: permissions,
			},
			parsed_specials=[],
		)

		m_ldap_user.parse_write_permissions(
			m_ldap_user.attributes[LOCAL_ATTR_PERMISSIONS]
		)
		if expected:
			assert set(m_ldap_user.parsed_specials) == {LOCAL_ATTR_UAC}
		else:
			assert not m_ldap_user.parsed_specials
		assert m_ldap_user.attributes.get(LOCAL_ATTR_UAC, None) == expected


class TestPerformGroupOperations:
	@pytest.mark.parametrize(
		"add_groups, rm_groups, expected_add, expected_rm",
		(
			(
				["mock_group_1"],
				["mock_group_2"],
				True,
				True,
			),
			(
				["mock_group_1"],
				[],
				True,
				False,
			),
			(
				[],
				["mock_group_2"],
				False,
				True,
			),
		),
	)
	def test_success(
		self,
		add_groups: list,
		rm_groups: list,
		expected_add: bool,
		expected_rm: bool,
		f_connection: LDAPConnectionProtocol,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			distinguished_name="mock_dn",
			attributes={
				LOCAL_ATTR_USER_ADD_GROUPS: add_groups,
				LOCAL_ATTR_USER_RM_GROUPS: rm_groups,
			},
			parsed_specials=[
				LOCAL_ATTR_USER_ADD_GROUPS,
				LOCAL_ATTR_USER_RM_GROUPS,
			],
		)
		m_ldap_user.connection = f_connection
		m_ldap_user.perform_group_operations(
			groups_to_add=add_groups,
			groups_to_remove=rm_groups,
		)

		if expected_add:
			m_add_members_to_groups: MockType = (
				f_connection.extend.microsoft.add_members_to_groups
			)
			m_add_members_to_groups.assert_called_once_with(
				"mock_dn", set(add_groups)
			)
		if expected_rm:
			m_remove_members_from_groups: MockType = (
				f_connection.extend.microsoft.remove_members_from_groups
			)
			m_remove_members_from_groups.assert_called_once_with(
				"mock_dn", set(rm_groups)
			)

	@pytest.mark.parametrize(
		"add_groups, rm_groups",
		(
			(
				["mock_group_1", "mock_group_2"],
				["mock_group_2"],
			),
			(
				["mock_group_1"],
				["mock_group_1"],
			),
			(
				["mock_group_1"],
				["mock_group_1", "mock_group_2"],
			),
		),
	)
	def test_raises_bad_group_selection(
		self,
		add_groups: list,
		rm_groups: list,
		f_connection: LDAPConnectionProtocol,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			distinguished_name="mock_dn",
			attributes={
				LOCAL_ATTR_USER_ADD_GROUPS: add_groups,
				LOCAL_ATTR_USER_RM_GROUPS: rm_groups,
			},
			parsed_specials=[
				LOCAL_ATTR_USER_ADD_GROUPS,
				LOCAL_ATTR_USER_RM_GROUPS,
			],
		)
		m_ldap_user.connection = f_connection
		with pytest.raises(exc_user.BadGroupSelection):
			m_ldap_user.perform_group_operations(
				groups_to_add=add_groups,
				groups_to_remove=rm_groups,
			)

		m_add_members_to_groups: MockType = (
			f_connection.extend.microsoft.add_members_to_groups
		)
		m_add_members_to_groups.assert_not_called()
		m_remove_members_from_groups: MockType = (
			f_connection.extend.microsoft.remove_members_from_groups
		)
		m_remove_members_from_groups.assert_not_called()
		assert m_ldap_user.parsed_specials == [
			LOCAL_ATTR_USER_ADD_GROUPS,
			LOCAL_ATTR_USER_RM_GROUPS,
		]

	@pytest.mark.parametrize(
		"add_groups, rm_groups",
		(
			(
				["mock_group_1", "mock_group_2"],
				["mock_group_2"],
			),
			(
				["mock_group_1"],
				["mock_group_1"],
			),
			(
				["mock_group_1"],
				["mock_group_1", "mock_group_2"],
			),
		),
	)
	def test_raises_core_exc(
		self,
		add_groups: list,
		rm_groups: list,
		f_connection: LDAPConnectionProtocol,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init(
			distinguished_name="mock_dn",
			attributes={
				LOCAL_ATTR_USER_ADD_GROUPS: add_groups,
				LOCAL_ATTR_USER_RM_GROUPS: rm_groups,
			},
			parsed_specials=[],
		)
		m_ldap_user.connection = f_connection
		with pytest.raises(exc_base.CoreException):
			m_ldap_user.perform_group_operations(
				groups_to_add=add_groups,
				groups_to_remove=rm_groups,
			)

		m_add_members_to_groups: MockType = (
			f_connection.extend.microsoft.add_members_to_groups
		)
		m_add_members_to_groups.assert_not_called()
		m_remove_members_from_groups: MockType = (
			f_connection.extend.microsoft.remove_members_from_groups
		)
		m_remove_members_from_groups.assert_not_called()
		assert not m_ldap_user.parsed_specials


class TestPropertyIsEnabled:
	def test_raises_no_entry(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init()
		with pytest.raises(ValueError, match="Entry is required to check"):
			m_ldap_user.is_enabled

	def test_raises_entry_has_no_uac(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = {}
		m_ldap_user = f_ldap_user_no_init()
		with pytest.raises(ValueError, match="Entry is required to check"):
			m_ldap_user.is_enabled

	def test_success_mocked(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_list_user_perms = mocker.patch(
			"core.models.ldap_user.list_user_perms", return_value=True
		)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = [LDAP_ATTR_UAC]
		m_ldap_user = f_ldap_user_no_init(entry=m_entry)

		assert not m_ldap_user.is_enabled
		m_list_user_perms.assert_called_once_with(
			user=m_ldap_user.entry,
			perm_search=LDAP_UF_ACCOUNT_DISABLE,
		)

	@pytest.mark.parametrize(
		"permissions, expected",
		(
			(
				calc_permissions([LDAP_UF_NORMAL_ACCOUNT]),
				True,
			),
			(
				calc_permissions(
					[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_ACCOUNT_DISABLE]
				),
				False,
			),
		),
	)
	def test_success(
		self,
		permissions: list,
		expected: bool,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = [LDAP_ATTR_UAC]
		m_attr_username = mocker.Mock()
		m_attr_username.value = "testuser"
		m_attr = mocker.Mock()
		setattr(m_entry, LDAP_ATTR_USERNAME_SAMBA_ADDS, m_attr)
		m_attr.value = permissions
		m_attr.values = [permissions]
		setattr(m_entry, LDAP_ATTR_UAC, m_attr)
		m_ldap_user = f_ldap_user_no_init(entry=m_entry)

		assert m_ldap_user.is_enabled == expected


class TestPropertyCanChangePassword:
	def test_raises_no_entry(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_ldap_user = f_ldap_user_no_init()
		with pytest.raises(ValueError, match="Entry is required to check"):
			m_ldap_user.can_change_password

	def test_raises_entry_has_no_uac(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = {}
		m_ldap_user = f_ldap_user_no_init()
		with pytest.raises(ValueError, match="Entry is required to check"):
			m_ldap_user.can_change_password

	def test_success_mocked(
		self,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_list_user_perms = mocker.patch(
			"core.models.ldap_user.list_user_perms", return_value=True
		)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = [LDAP_ATTR_UAC]
		m_ldap_user = f_ldap_user_no_init(entry=m_entry)

		assert not m_ldap_user.can_change_password
		m_list_user_perms.assert_called_once_with(
			user=m_ldap_user.entry,
			perm_search=LDAP_UF_PASSWD_CANT_CHANGE,
		)

	@pytest.mark.parametrize(
		"permissions, expected",
		(
			(
				calc_permissions([LDAP_UF_NORMAL_ACCOUNT]),
				True,
			),
			(
				calc_permissions(
					[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_PASSWD_CANT_CHANGE]
				),
				False,
			),
		),
	)
	def test_success(
		self,
		permissions: list,
		expected: bool,
		mocker: MockerFixture,
		f_ldap_user_no_init: InitlessLDAPUserFactory,
	):
		mocker.patch.object(LDAPUser, "__init__", return_value=None)
		m_entry = mocker.Mock()
		m_entry.entry_attributes = [LDAP_ATTR_UAC]
		m_attr_username = mocker.Mock()
		m_attr_username.value = "testuser"
		m_attr = mocker.Mock()
		setattr(m_entry, LDAP_ATTR_USERNAME_SAMBA_ADDS, m_attr)
		m_attr.value = permissions
		m_attr.values = [permissions]
		setattr(m_entry, LDAP_ATTR_UAC, m_attr)
		m_ldap_user = f_ldap_user_no_init(entry=m_entry)

		assert m_ldap_user.can_change_password == expected
