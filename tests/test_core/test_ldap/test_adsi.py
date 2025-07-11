import pytest
from pytest_mock import MockType
from core.ldap.defaults import LDAP_FIELD_MAP
from core.ldap.adsi import (
	join_ldap_filter,
	LDAP_FILTER_AND,
	LDAP_FILTER_OR,
	LDAP_UF_ACCOUNT_DISABLE,
	LDAP_UF_DONT_EXPIRE_PASSWD,
	LDAP_UF_NORMAL_ACCOUNT,
	LDAP_PERMS,
	bin_as_hex,
	bin_as_str,
	calc_permissions,
	merge_val_bin,
	parse_permissions_int,
	list_user_perms,
	LengthError,
)


@pytest.mark.parametrize(
	"filter_string,filter_add,expression,negate,negate_add,expected",
	(
		# Simple AND expression
		(
			"objectClass=person",
			"sAMAccountName=testuser",
			LDAP_FILTER_AND,
			False,
			False,
			f"({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser))",
		),
		# Simple OR expression
		(
			"objectClass=person",
			"sAMAccountName=testuser",
			LDAP_FILTER_OR,
			False,
			False,
			f"({LDAP_FILTER_OR}(objectClass=person)(sAMAccountName=testuser))",
		),
		# AND expression with negate add
		(
			"objectClass=person",
			"sAMAccountName=testuser",
			LDAP_FILTER_AND,
			False,
			True,
			f"({LDAP_FILTER_AND}(objectClass=person)(!(sAMAccountName=testuser)))",
		),
		# AND expression with full negate
		(
			"objectClass=person",
			"sAMAccountName=testuser",
			LDAP_FILTER_AND,
			True,
			False,
			f"(!({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser)))",
		),
		# AND expression with uneven encapsulation
		(
			"(objectClass=person)",
			"sAMAccountName=testuser",
			LDAP_FILTER_AND,
			False,
			False,
			f"({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser))",
		),
		# AND with word expression
		(
			"(objectClass=person)",
			"sAMAccountName=testuser",
			"and",
			False,
			False,
			f"({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser))",
		),
		# OR with word expression
		(
			"(objectClass=person)",
			"sAMAccountName=testuser",
			"or",
			False,
			False,
			f"({LDAP_FILTER_OR}(objectClass=person)(sAMAccountName=testuser))",
		),
		# Single Attribute filter
		(
			"",
			"sAMAccountName=testuser",
			LDAP_FILTER_AND,
			False,
			False,
			"(sAMAccountName=testuser)",
		),
		# OR expression merging
		(
			f"({LDAP_FILTER_OR}(sAMAccountName=user1)(sAMAccountName=user2))",
			"sAMAccountName=user3",
			LDAP_FILTER_OR,
			False,
			False,
			f"({LDAP_FILTER_OR}(sAMAccountName=user1)(sAMAccountName=user2)(sAMAccountName=user3))",
		),
		# OR expression merging with negate add
		(
			f"({LDAP_FILTER_OR}(sAMAccountName=user1)(sAMAccountName=user2))",
			"sAMAccountName=user3",
			LDAP_FILTER_OR,
			False,
			True,
			f"({LDAP_FILTER_OR}(sAMAccountName=user1)(sAMAccountName=user2)(!(sAMAccountName=user3)))",
		),
		# OR expression merging with full negate
		(
			f"({LDAP_FILTER_OR}(sAMAccountName=user1)(sAMAccountName=user2))",
			"sAMAccountName=user3",
			LDAP_FILTER_OR,
			True,
			False,
			f"(!({LDAP_FILTER_OR}(sAMAccountName=user1)(sAMAccountName=user2)(sAMAccountName=user3)))",
		),
		# AND expression merging
		(
			f"({LDAP_FILTER_AND}(sAMAccountName=user1)(sAMAccountName=user2))",
			"sAMAccountName=user3",
			LDAP_FILTER_AND,
			False,
			False,
			f"({LDAP_FILTER_AND}(sAMAccountName=user1)(sAMAccountName=user2)(sAMAccountName=user3))",
		),
		# AND with OR merging
		(
			f"({LDAP_FILTER_AND}(sAMAccountName=user1)(sAMAccountName=user2))",
			"sAMAccountName=user3",
			LDAP_FILTER_OR,
			False,
			False,
			f"({LDAP_FILTER_OR}({LDAP_FILTER_AND}(sAMAccountName=user1)(sAMAccountName=user2))(sAMAccountName=user3))",
		),
	),
)
def test_join_ldap_filter(
	filter_string, filter_add, expression, negate, negate_add, expected
):
	assert (
		join_ldap_filter(
			filter_string, filter_add, expression, negate, negate_add
		)
		== expected
	)


def test_join_ldap_filter_raises_empty_string():
	with pytest.raises(ValueError):
		join_ldap_filter("", "", LDAP_FILTER_AND)


def test_join_ldap_filter_raises_invalid_expression():
	with pytest.raises(ValueError):
		join_ldap_filter("", "objectClass=person", "A")


@pytest.mark.parametrize(
	"input_value, expected",
	(
		(10, "00000000000000000000000000001010"),  # Positive integer
		(123456789, "00000111010110111100110100010101"),  # Large integer
		(0, "00000000000000000000000000000000"),  # Zero
		(
			"255",
			"00000000000000000000000011111111",
		),  # String representation of integer
		("1010", "00000000000000000000000000001010"),  # Binary string
	),
)
def test_bin_as_str(input_value, expected):
	assert bin_as_str(input_value) == expected


@pytest.mark.parametrize(
	"invalid_input",
	(
		-10,  # Negative integer
		"abc",  # Non-integer string
	),
)
def test_bin_as_str_invalid(invalid_input):
	with pytest.raises(ValueError):
		bin_as_str(invalid_input)


@pytest.mark.parametrize(
	"input_value, expected",
	[
		("1010", "0x000a"),  # Binary string
		("00001010", "0x000a"),  # Binary string with leading zeros
		("1111111111111111", "0xffff"),  # Larger binary string
		("0000", "0x0000"),  # Binary string representing zero
	],
)
def test_bin_as_hex(input_value, expected):
	assert bin_as_hex(input_value) == expected


@pytest.mark.parametrize(
	"invalid_input",
	(
		"",  # Empty string
		"1234",  # Non-binary string
	),
)
def test_bin_as_hex_invalid(invalid_input):
	with pytest.raises(ValueError):
		bin_as_hex(invalid_input)


@pytest.mark.parametrize(
	"perm_a, perm_b, expected",
	(
		(
			LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"],
			LDAP_PERMS[LDAP_UF_DONT_EXPIRE_PASSWD]["val_bin"],
			"00000000000000010000001000000000",
		),
	),
)
def test_merge_val_bin(perm_a, perm_b, expected):
	assert merge_val_bin(perm_a, perm_b) == expected


@pytest.mark.parametrize(
	"perm_a, perm_b", ((LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"], 1),)
)
def test_merge_val_bin_invalid_type(perm_a, perm_b):
	with pytest.raises(TypeError):
		merge_val_bin(perm_a, perm_b)


@pytest.mark.parametrize(
	"perm_a, perm_b",
	((LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"], "000123"),),
)
def test_merge_val_bin_invalid_length(perm_a, perm_b):
	with pytest.raises(LengthError):
		merge_val_bin(perm_a, perm_b)


@pytest.mark.parametrize(
	"perm_a, perm_b",
	(
		("000123".zfill(32), LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"]),
		(LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"], "000123".zfill(32)),
	),
)
def test_merge_val_bin_invalid_value(perm_a, perm_b):
	with pytest.raises(ValueError):
		merge_val_bin(perm_a, perm_b)


@pytest.mark.parametrize(
	"raw_user_permissions, expected",
	(
		(LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"], [LDAP_UF_NORMAL_ACCOUNT]),
		(
			LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"],
			[LDAP_UF_NORMAL_ACCOUNT],
		),
		(
			LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"]
			+ LDAP_PERMS[LDAP_UF_DONT_EXPIRE_PASSWD]["value"],
			[LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_NORMAL_ACCOUNT],
		),
		(
			merge_val_bin(
				LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"],
				LDAP_PERMS[LDAP_UF_DONT_EXPIRE_PASSWD]["val_bin"],
			),
			[LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_NORMAL_ACCOUNT],
		),
	),
)
def test_parse_permissions_int(raw_user_permissions, expected):
	assert parse_permissions_int(raw_user_permissions) == expected


def test_parse_permissions_int_value_error():
	with pytest.raises(ValueError):
		parse_permissions_int("abcd1234")


def sum_permissions(perm_list: list[str]) -> int:
	"""Sums LDAP_PERMS integer values"""
	return sum(LDAP_PERMS[k]["value"] for k in perm_list)


@pytest.mark.parametrize(
	"permission_list, perm_add, perm_remove, expected",
	(
		# Calculate permissions without operations
		(
			[LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_NORMAL_ACCOUNT],
			None,
			None,
			[LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_NORMAL_ACCOUNT],
		),
		# Calculate permissions that are repeated
		(
			[
				LDAP_UF_DONT_EXPIRE_PASSWD,
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_NORMAL_ACCOUNT,
			],
			None,
			None,
			[LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_NORMAL_ACCOUNT],
		),
		# Add single permission to multiple
		(
			[LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_NORMAL_ACCOUNT],
			LDAP_UF_ACCOUNT_DISABLE,
			None,
			[
				LDAP_UF_ACCOUNT_DISABLE,
				LDAP_UF_DONT_EXPIRE_PASSWD,
				LDAP_UF_NORMAL_ACCOUNT,
			],
		),
		# Add single permission to list with single permission
		(
			[LDAP_UF_NORMAL_ACCOUNT],
			LDAP_UF_ACCOUNT_DISABLE,
			None,
			[LDAP_UF_ACCOUNT_DISABLE, LDAP_UF_NORMAL_ACCOUNT],
		),
		# Add multiple permissions to list with single permission
		(
			[LDAP_UF_NORMAL_ACCOUNT],
			[LDAP_UF_ACCOUNT_DISABLE, LDAP_UF_DONT_EXPIRE_PASSWD],
			None,
			[
				LDAP_UF_ACCOUNT_DISABLE,
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_DONT_EXPIRE_PASSWD,
			],
		),
		# Add multiple with redundant permissions
		(
			[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
			[LDAP_UF_ACCOUNT_DISABLE, LDAP_UF_DONT_EXPIRE_PASSWD],
			None,
			[
				LDAP_UF_ACCOUNT_DISABLE,
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_DONT_EXPIRE_PASSWD,
			],
		),
		# Remove single permission
		(
			[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_ACCOUNT_DISABLE],
			None,
			LDAP_UF_ACCOUNT_DISABLE,
			[LDAP_UF_NORMAL_ACCOUNT],
		),
		# Remove multiple permissions
		(
			[
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_ACCOUNT_DISABLE,
				LDAP_UF_DONT_EXPIRE_PASSWD,
			],
			None,
			[LDAP_UF_ACCOUNT_DISABLE, LDAP_UF_DONT_EXPIRE_PASSWD],
			[LDAP_UF_NORMAL_ACCOUNT],
		),
		# Remove multiple permissions with an unexisting permission
		(
			[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
			None,
			[LDAP_UF_ACCOUNT_DISABLE, LDAP_UF_DONT_EXPIRE_PASSWD],
			[LDAP_UF_NORMAL_ACCOUNT],
		),
	),
)
def test_calc_permissions(permission_list, perm_add, perm_remove, expected):
	assert calc_permissions(
		permission_list, perm_add, perm_remove
	) == sum_permissions(expected)


def test_calc_permission_type_error():
	with pytest.raises(TypeError):
		calc_permissions(LDAP_UF_ACCOUNT_DISABLE)


@pytest.mark.parametrize(
	"userAccountControl, perm_search, expected",
	(
		(
			[
				LDAP_UF_ACCOUNT_DISABLE,
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_DONT_EXPIRE_PASSWD,
			],
			None,
			[
				LDAP_UF_ACCOUNT_DISABLE,
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_DONT_EXPIRE_PASSWD,
			].sort(),
		),
		(
			[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
			None,
			[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD].sort(),
		),
		(
			[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
			LDAP_UF_NORMAL_ACCOUNT,
			True,
		),
	),
)
def test_list_user_perms_user_object(
	userAccountControl, perm_search, expected, mocker
):
	user: MockType = mocker.MagicMock()
	user.userAccountControl.value = sum_permissions(userAccountControl)
	if isinstance(expected, bool):
		assert list_user_perms(user, perm_search) == expected
	else:
		assert list_user_perms(user, perm_search).sort() == expected


def test_list_user_perms_user_object_should_return_none(mocker):
	user: MockType = mocker.MagicMock()
	user.userAccountControl.values = []
	user.userAccountControl.value = user.userAccountControl.values
	assert list_user_perms(user, None) is None


def test_list_user_perms_user_object_uac_is_none(mocker):
	user: MockType = mocker.MagicMock()
	user.userAccountControl = None
	with pytest.raises(ValueError):
		list_user_perms(user, None)


def test_list_user_perms_user_object_has_no_uac(mocker):
	with pytest.raises(ValueError):
		list_user_perms(object(), None)


def test_list_user_perms_user_dict_has_no_uac(mocker):
	with pytest.raises(ValueError):
		list_user_perms({}, None, False)


@pytest.mark.parametrize(
	"userAccountControl, perm_search, expected",
	(
		(
			[
				LDAP_UF_ACCOUNT_DISABLE,
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_DONT_EXPIRE_PASSWD,
			],
			None,
			[
				LDAP_UF_ACCOUNT_DISABLE,
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_DONT_EXPIRE_PASSWD,
			].sort(),
		),
		(
			[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD],
			None,
			[LDAP_UF_NORMAL_ACCOUNT, LDAP_UF_DONT_EXPIRE_PASSWD].sort(),
		),
	),
)
def test_list_user_perms_user_dict(userAccountControl, perm_search, expected):
	user = {
		LDAP_FIELD_MAP["username"]: "testuser",
		"userAccountControl": sum_permissions(userAccountControl),
	}
	assert list_user_perms(user, perm_search, False).sort() == expected
