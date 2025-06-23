########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture

################################################################################
from core.ldap.adsi import join_ldap_filter
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_CLASS_LDAP,
	LOG_ACTION_UPDATE,
	LOG_ACTION_RENAME,
	LOG_ACTION_MOVE,
)
from core.views.mixins.ldap.organizational_unit import (
	OrganizationalUnitMixin,
	LDAP_DEFAULT_DIRTREE_FILTER,
)
from core.models.ldap_settings_runtime import RuntimeSettingsSingleton
from tests.test_core.conftest import RuntimeSettingsFactory
from core.exceptions import ldap as exc_ldap, dirtree as exc_dirtree
from rest_framework.exceptions import ValidationError


@pytest.fixture(autouse=True)
def f_runtime_settings(g_runtime_settings: RuntimeSettingsFactory):
	return g_runtime_settings(
		patch_path="core.views.mixins.ldap.organizational_unit.RuntimeSettings"
	)


@pytest.fixture
def f_logger(mocker: MockerFixture):
	return mocker.patch("core.views.mixins.ldap.organizational_unit.logger")


@pytest.fixture(autouse=True)
def f_log_mixin(mocker: MockerFixture) -> LogMixin:
	return mocker.patch(
		f"core.views.mixins.ldap.organizational_unit.DBLogMixin",
		mocker.MagicMock(),
	)


@pytest.fixture
def f_ou_mixin(mocker: MockerFixture):
	m_request = mocker.Mock()
	m_request.user.id = 1
	m_mixin = OrganizationalUnitMixin()
	m_mixin.ldap_connection = mocker.MagicMock()
	m_mixin.request = m_request
	return m_mixin


@pytest.fixture
def f_object_category_filter():
	def maker(**kwargs):
		flt = None
		for value in LDAP_DEFAULT_DIRTREE_FILTER["include"]["objectCategory"]:
			if value in kwargs:
				continue
			flt = join_ldap_filter(
				filter_string=flt,
				filter_to_add=f"objectCategory={value}",
				expression="|",
			)
		return flt

	return maker


@pytest.fixture
def f_object_class_filter():
	def maker(**kwargs):
		flt = None
		for value in LDAP_DEFAULT_DIRTREE_FILTER["include"]["objectClass"]:
			if value in kwargs:
				continue
			flt = join_ldap_filter(
				filter_string=flt,
				filter_to_add=f"objectClass={value}",
				expression="|",
			)
		return flt

	return maker


@pytest.fixture
def f_object_class_and_category_filter(
	f_object_category_filter, f_object_class_filter
):
	return f"{f_object_category_filter()[:-1]}{f_object_class_filter()[2:]}"


@pytest.mark.parametrize(
	"value, expected",
	(
		(
			"a",
			"a",
		),
		(("a",), "a"),
		(
			(
				"a",
				"b",
			),
			(
				"a",
				"b",
			),
		),
		(
			[
				"a",
			],
			"a",
		),
		(
			[
				"a",
				"b",
			],
			[
				"a",
				"b",
			],
		),
		([], None),
		(
			{
				"a",
			},
			"a",
		),
		(
			{
				"a",
				"b",
			},
			{
				"a",
				"b",
			},
		),
		({}, None),
	),
	ids=[
		"Single value",
		"Tuple with single value",
		"Tuple",
		"List with single value",
		"List",
		"Empty List",
		"Set with single value",
		"Set",
		"Empty Set",
	],
)
def test_cleanup_attr_value(
	value, expected, f_ou_mixin: OrganizationalUnitMixin
):
	assert f_ou_mixin.cleanup_attr_value(value=value) == expected


@pytest.mark.parametrize(
	"value, expected",
	(
		(
			"a",
			False,
		),
		(
			1,
			False,
		),
		(
			True,
			False,
		),
		(
			("a", "b"),
			True,
		),
		(
			["a", "b"],
			True,
		),
		(
			{"a", "b"},
			True,
		),
	),
	ids=[
		"Single str value",
		"Single int value",
		"Single bool value",
		"Tuple of str values",
		"List of str values",
		"Set of str values",
	],
)
def test_is_multi_value_attribute(
	value, expected, f_ou_mixin: OrganizationalUnitMixin
):
	assert (
		f_ou_mixin.is_multi_value_attribute("mockAttribute", value) == expected
	)


def test_is_multi_value_raises_validation_error(
	f_ou_mixin: OrganizationalUnitMixin,
):
	with pytest.raises(ValidationError):
		f_ou_mixin.is_multi_value_attribute("mockAttribute", b"some_bytes")


@pytest.mark.parametrize(
	"filter_type, filter_dict, expected",
	(
		# Simple cases
		(
			"include",
			{
				"objectClass": "user",
			},
			"(objectClass=user)",
		),
		(
			"exclude",
			{
				"objectClass": "user",
			},
			"(!(objectClass=user))",
		),
		(
			"iexact",
			{
				"objectClass": "user",
			},
			"(objectClass=user)",
		),
		(
			"contains",
			{
				"objectClass": "user",
			},
			"(objectClass=*user*)",
		),
		(
			"startswith",
			{
				"objectClass": "user",
			},
			"(objectClass=user*)",
		),
		(
			"endswith",
			{
				"objectClass": "user",
			},
			"(objectClass=*user)",
		),
		# Complex cases
		(
			"include",
			{
				"objectClass": "user",
				"distinguishedName": ["testdn1", "testdn2"],
			},
			"(|(objectClass=user)(distinguishedName=testdn1)(distinguishedName=testdn2))",
		),
		(
			"exclude",
			{"objectClass": "user", "distinguishedName": "testdn"},
			"(&(!(objectClass=user))(!(distinguishedName=testdn)))",
		),
		(
			"exclude",
			{
				"objectClass": ["user", "group"],
			},
			"(&(!(objectClass=user))(!(objectClass=group)))",
		),
		(
			"iexact",
			{"objectClass": ["user", "group"], "distinguishedName": "testdn"},
			"(&(objectClass=user)(objectClass=group)(distinguishedName=testdn))",
		),
		(
			"contains",
			{
				"givenName": ["john", "sam"],
				"sn": "johnson",
			},
			"(&(|(givenName=*john*)(givenName=*sam*))(sn=*johnson*))",
		),
		(
			"startswith",
			{
				"givenName": ["john", "sam"],
				"sn": "johnson",
			},
			"(&(|(givenName=john*)(givenName=sam*))(sn=johnson*))",
		),
		(
			"endswith",
			{
				"givenName": ["john", "sam"],
				"sn": "johnson",
			},
			"(&(|(givenName=*john)(givenName=*sam))(sn=*johnson))",
		),
		(
			"gte",
			{"mockAttribute1": 10},
			"(mockAttribute1>=10)",
		),
		(
			"gte",
			{
				"mockAttribute1": 5,
				"mockAttribute2": 1,
			},
			"(&(mockAttribute1>=5)(mockAttribute2>=1))",
		),
	),
)
def test_process_ldap_filter_type(
	filter_type: str,
	filter_dict: dict,
	expected: str,
	f_ou_mixin: OrganizationalUnitMixin,
):
	assert (
		f_ou_mixin.process_ldap_filter_type(
			filter_type, filter_dict
		).to_string()
		== expected
	)


def test_process_ldap_filter_type_raises_on_iterable(
	f_ou_mixin: OrganizationalUnitMixin,
):
	with pytest.raises(ValidationError):
		f_ou_mixin.process_ldap_filter_type("gte", {"mockAttribute": [1]})


@pytest.mark.parametrize(
	"test_dict",
	(
		{"some_bad_key": {}},
		{"include": []},
	),
	ids=["Invalid filter dict key", "Invalid filter dict condition type"],
)
def test_validate_ldap_filter_dict_raises_validation_error(
	f_ou_mixin: OrganizationalUnitMixin,
	test_dict: dict,
):
	with pytest.raises(ValidationError):
		f_ou_mixin.validate_filter_dict(filter_dict=test_dict)


def test_process_ldap_filter_no_defaults(f_ou_mixin: OrganizationalUnitMixin):
	expected = "(|(objectClass=person)(objectClass=user))"
	assert (
		f_ou_mixin.process_ldap_filter(
			data_filter={
				"include": {
					"objectClass": [
						"person",
						"user",
					]
				}
			},
			default_filter=False,
		).to_string()
		== expected
	)


def test_process_ldap_filter_with_defaults(
	f_ou_mixin: OrganizationalUnitMixin,
	f_object_class_and_category_filter,
):
	result = f_ou_mixin.process_ldap_filter(
		data_filter={}, default_filter=True
	).to_string()

	expected = f_object_class_and_category_filter
	assert result == expected


def test_process_ldap_filter_with_data_and_defaults(
	f_ou_mixin: OrganizationalUnitMixin,
	f_object_category_filter,
	f_object_class_filter,
):
	result = f_ou_mixin.process_ldap_filter(
		data_filter={"exclude": {"objectClass": "user"}}, default_filter=True
	).to_string()
	expected = f"{f_object_category_filter()[:-1]}{f_object_class_filter(user=None)[2:]}"
	expected = f"(&{expected}(!(objectClass=user)))"
	assert result == expected


@pytest.fixture
def f_distinguished_name(f_runtime_settings: RuntimeSettingsSingleton):
	return f"CN=test,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}"


def test_move_or_rename_object_raises_dn_validation_exception(
	mocker: MockerFixture,
	f_ou_mixin: OrganizationalUnitMixin,
	f_logger,
):
	mocker.patch(
		"core.views.mixins.ldap.organizational_unit.parse_dn",
		side_effect=Exception,
	)
	with pytest.raises(exc_ldap.DistinguishedNameValidationError):
		f_ou_mixin.move_or_rename_object(distinguished_name="some_bad_dn")
	f_logger.exception.assert_called_once()


def test_move_or_rename_raises_no_rdn_or_target(
	f_ou_mixin: OrganizationalUnitMixin,
	f_runtime_settings: RuntimeSettingsSingleton,
):
	m_distinguishedName = (
		f"PA=something,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}"
	)
	with pytest.raises(exc_dirtree.DirtreeDistinguishedNameConflict):
		f_ou_mixin.move_or_rename_object(distinguished_name=m_distinguishedName)


def test_move_or_rename_raises_bad_dn_identifier(
	f_ou_mixin: OrganizationalUnitMixin,
	f_runtime_settings: RuntimeSettingsSingleton,
):
	m_distinguishedName = (
		f"PA=something,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}"
	)
	with pytest.raises(exc_ldap.LDIFBadField) as e:
		f_ou_mixin.move_or_rename_object(
			distinguished_name=m_distinguishedName, target_rdn="new name"
		)
	assert e._excinfo[1].detail["field"] == "original_rdn"


@pytest.mark.parametrize(
	"target_rdn, expected_exc, detail",
	(
		(
			"PA=new name",
			exc_ldap.LDIFBadField,
			{"field": "new_rdn"},
		),
		(
			"CN=CN=new name",
			exc_ldap.DistinguishedNameValidationError,
			None,
		),
	),
)
def test_move_or_rename_raises_bad_rdn_identifier(
	f_ou_mixin: OrganizationalUnitMixin,
	f_distinguished_name: str,
	target_rdn: str,
	expected_exc,
	detail,
):
	with pytest.raises(expected_exc) as e:
		f_ou_mixin.move_or_rename_object(
			distinguished_name=f_distinguished_name, target_rdn=target_rdn
		)
	if detail:
		assert e._excinfo[1].detail["field"] == detail["field"]


def test_move_or_rename_rdn_same_as_current(
	f_ou_mixin: OrganizationalUnitMixin,
	f_distinguished_name: str,
):
	with pytest.raises(exc_dirtree.DirtreeNewNameIsOld):
		f_ou_mixin.move_or_rename_object(
			distinguished_name=f_distinguished_name,
			target_rdn=f_distinguished_name.split(",")[0],
		)


@pytest.mark.parametrize(
	"target_rdn",
	(
		"new name",
		"CN=new name",
	),
)
def test_move_or_rename_object_rename_only(
	target_rdn: str,
	f_ou_mixin: OrganizationalUnitMixin,
	f_distinguished_name: str,
	f_log_mixin: LogMixin,
):
	expected_rdn = (
		f"CN={target_rdn}" if not target_rdn.startswith("CN=") else target_rdn
	)
	expected_path = ",".join(f_distinguished_name.split(",")[1:])

	f_ou_mixin.move_or_rename_object(
		distinguished_name=f_distinguished_name, target_rdn=target_rdn
	)
	f_ou_mixin.ldap_connection.modify_dn.assert_called_once_with(
		dn=f_distinguished_name, relative_dn="CN=new name"
	)
	f_log_mixin.log.assert_called_once_with(
		user=f_ou_mixin.request.user.id,
		operation_type=LOG_ACTION_RENAME,
		log_target_class=LOG_CLASS_LDAP,
		log_target=f"{f_distinguished_name} to {expected_rdn},{expected_path}",
	)


def test_move_or_rename_object_move_only(
	f_ou_mixin: OrganizationalUnitMixin,
	f_runtime_settings: RuntimeSettingsSingleton,
	f_distinguished_name: str,
	f_log_mixin: LogMixin,
):
	m_target_path = f"OU=SomeUnit,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}"
	m_rdn = f_distinguished_name.split(",")[0]
	expected_dn = f"{m_rdn},{m_target_path}"
	f_ou_mixin.move_or_rename_object(
		distinguished_name=f_distinguished_name, target_path=m_target_path
	)
	f_ou_mixin.ldap_connection.modify_dn.assert_called_once_with(
		dn=f_distinguished_name, relative_dn=m_rdn, new_superior=m_target_path
	)
	f_log_mixin.log.assert_called_once_with(
		user=f_ou_mixin.request.user.id,
		operation_type=LOG_ACTION_MOVE,
		log_target_class=LOG_CLASS_LDAP,
		log_target=f"{f_distinguished_name} to {expected_dn}",
	)


@pytest.mark.parametrize(
	"target_rdn",
	(
		"new name",
		"CN=new name",
	),
)
def test_move_or_rename_object_both_ops(
	target_rdn: str,
	f_ou_mixin: OrganizationalUnitMixin,
	f_runtime_settings: RuntimeSettingsSingleton,
	f_distinguished_name: str,
	f_log_mixin: LogMixin,
):
	m_target_path = f"OU=SomeUnit,{f_runtime_settings.LDAP_AUTH_SEARCH_BASE}"
	expected_rdn = (
		f"CN={target_rdn}" if not target_rdn.startswith("CN=") else target_rdn
	)
	expected_dn = f"{expected_rdn},{m_target_path}"
	f_ou_mixin.move_or_rename_object(
		distinguished_name=f_distinguished_name,
		target_rdn=target_rdn,
		target_path=m_target_path,
	)
	f_ou_mixin.ldap_connection.modify_dn.assert_called_once_with(
		dn=f_distinguished_name,
		relative_dn=expected_rdn,
		new_superior=m_target_path,
	)
	f_log_mixin.log.assert_called_once_with(
		user=f_ou_mixin.request.user.id,
		operation_type=LOG_ACTION_UPDATE,
		log_target_class=LOG_CLASS_LDAP,
		log_target=f"{f_distinguished_name} to {expected_dn}",
	)


@pytest.mark.parametrize(
	"ldap_exc_description, expected_code",
	(
		("entryAlreadyExists", 409),
		("unknownException", 500),
	),
)
def test_move_or_rename_object_ldap_server_raises(
	mocker: MockerFixture,
	ldap_exc_description: str,
	expected_code: int,
	f_ou_mixin: OrganizationalUnitMixin,
	f_distinguished_name: str,
	f_logger,
):
	m_result = mocker.MagicMock()
	m_result.description = ldap_exc_description
	f_ou_mixin.ldap_connection.result = m_result
	f_ou_mixin.ldap_connection.modify_dn.side_effect = Exception
	with pytest.raises(exc_dirtree.DirtreeMove) as e:
		f_ou_mixin.move_or_rename_object(
			distinguished_name=f_distinguished_name, target_rdn="mock"
		)
	f_logger.exception.assert_called_once()
	assert e._excinfo[1].detail["code"] == expected_code
