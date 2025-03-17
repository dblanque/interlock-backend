import pytest
from interlock_backend.ldap.defaults import LDAP_DIRTREE_OU_FILTER
from interlock_backend.ldap.adsi import (
    search_filter_add,
    search_filter_from_dict,
    LDAP_FILTER_AND,
    LDAP_FILTER_OR,
    LDAP_UF_DONT_EXPIRE_PASSWD,
    LDAP_UF_NORMAL_ACCOUNT,
    LDAP_PERMS,
    bin_as_hex,
    bin_as_str,
    calc_permissions,
    merge_val_bin,
    parse_permissions_int,
    LengthError
)

@pytest.mark.parametrize(
    "filter_string,filter_add,operator,negate,expected",
    (
        (
            "objectClass=person",
            "sAMAccountName=testuser",
            LDAP_FILTER_AND,
            False,
            f"({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser))"
        ),
        (
            "objectClass=person",
            "sAMAccountName=testuser",
            LDAP_FILTER_OR,
            False,
            f"({LDAP_FILTER_OR}(objectClass=person)(sAMAccountName=testuser))"
        ),
        (
            "objectClass=person",
            "sAMAccountName=testuser",
            LDAP_FILTER_AND,
            True,
            f"({LDAP_FILTER_AND}(objectClass=person)(!(sAMAccountName=testuser)))"
        ),
        (
            "(objectClass=person)",
            "sAMAccountName=testuser",
            LDAP_FILTER_AND,
            False,
            f"({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser))"
        ),
        (
            "(objectClass=person)",
            "sAMAccountName=testuser",
            "and",
            False,
            f"({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser))"
        ),
        (
            "(objectClass=person)",
            "sAMAccountName=testuser",
            "or",
            False,
            f"({LDAP_FILTER_OR}(objectClass=person)(sAMAccountName=testuser))"
        ),
        (
            "",
            "sAMAccountName=testuser",
            LDAP_FILTER_AND,
            False,
            f"(sAMAccountName=testuser)"
        ),
    )
)
def test_search_filter_add(filter_string,filter_add,operator,negate,expected):
    assert search_filter_add(filter_string,filter_add,operator,negate) == expected

def test_search_filter_add_raises_empty_string():
    with pytest.raises(ValueError):
        search_filter_add("", "",LDAP_FILTER_AND)

def test_search_filter_add_raises_invalid_operator():
    with pytest.raises(ValueError):
        search_filter_add("", "objectClass=person","A")

@pytest.mark.parametrize(
    "filter_dict,operator,reverse_key,expected",
    (
        (
            LDAP_DIRTREE_OU_FILTER,
            LDAP_FILTER_OR,
            False,
            f"({LDAP_FILTER_OR}({LDAP_FILTER_OR}({LDAP_FILTER_OR}(objectCategory=organizationalUnit)(objectCategory=top))(objectCategory=container))(objectClass=builtinDomain))"
        ),
        (
            {
                "objectClass":["person", "user"],
                "sAMAccountName":"testuser"
            },
            LDAP_FILTER_OR,
            True,
            f"(|(|(objectClass=person)(objectClass=user))(sAMAccountName=testuser))"
        ),
        (
            {
                "objectClass":"person",
                "sAMAccountName":"testuser"
            },
            LDAP_FILTER_AND,
            True,
            f"({LDAP_FILTER_AND}(objectClass=person)(sAMAccountName=testuser))"
        ),
    )
)
def test_search_filter_from_dict(filter_dict, operator, reverse_key, expected):
    assert search_filter_from_dict(filter_dict, operator, reverse_key) == expected

@pytest.mark.parametrize("input_value, expected", (
    (10, "00000000000000000000000000001010"),  # Positive integer
    (123456789, "00000111010110111100110100010101"),  # Large integer
    (0, "00000000000000000000000000000000"),  # Zero
    ("255", "00000000000000000000000011111111"),  # String representation of integer
    ("1010", "00000000000000000000000000001010"),  # Binary string
))
def test_bin_as_str(input_value, expected):
    assert bin_as_str(input_value) == expected

@pytest.mark.parametrize("invalid_input", (
    -10,  # Negative integer
    "abc",  # Non-integer string
))
def test_bin_as_str_invalid(invalid_input):
    with pytest.raises(ValueError):
        bin_as_str(invalid_input)

@pytest.mark.parametrize("input_value, expected", [
    ("1010", "0x000a"),  # Binary string
    ("00001010", "0x000a"),  # Binary string with leading zeros
    ("1111111111111111", "0xffff"),  # Larger binary string
    ("0000", "0x0000"),  # Binary string representing zero
])
def test_bin_as_hex(input_value, expected):
    assert bin_as_hex(input_value) == expected

@pytest.mark.parametrize("invalid_input", (
    "",  # Empty string
    "1234",  # Non-binary string
))
def test_bin_as_hex_invalid(invalid_input):
    with pytest.raises(ValueError):
        bin_as_hex(invalid_input)

@pytest.mark.parametrize("perm_a, perm_b, expected", (
    (LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"], LDAP_PERMS[LDAP_UF_DONT_EXPIRE_PASSWD]["val_bin"], '00000000000000010000001000000000'),
))
def test_merge_val_bin(perm_a, perm_b, expected):
    assert merge_val_bin(perm_a, perm_b) == expected

@pytest.mark.parametrize("perm_a, perm_b", (
    (LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"], 1),
))
def test_merge_val_bin_invalid_type(perm_a, perm_b):
    with pytest.raises(TypeError):
        merge_val_bin(perm_a, perm_b)

@pytest.mark.parametrize("perm_a, perm_b", (
    (LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"], "000123"),
))
def test_merge_val_bin_invalid_length(perm_a, perm_b):
    with pytest.raises(LengthError):
        merge_val_bin(perm_a, perm_b)

@pytest.mark.parametrize("perm_a, perm_b", (
    (LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"], "000123".zfill(32)),
))
def test_merge_val_bin_invalid_value(perm_a, perm_b):
    with pytest.raises(ValueError):
        merge_val_bin(perm_a, perm_b)

@pytest.mark.parametrize("raw_user_permissions, expected", (
    (LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"], [ LDAP_UF_NORMAL_ACCOUNT ]),
    (LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"], [ LDAP_UF_NORMAL_ACCOUNT ]),
    (
        LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["value"] +
        LDAP_PERMS[LDAP_UF_DONT_EXPIRE_PASSWD]["value"],
        [ LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_NORMAL_ACCOUNT ]
    ),
    (
        merge_val_bin(
            LDAP_PERMS[LDAP_UF_NORMAL_ACCOUNT]["val_bin"], 
            LDAP_PERMS[LDAP_UF_DONT_EXPIRE_PASSWD]["val_bin"]
        ),
        [ LDAP_UF_DONT_EXPIRE_PASSWD, LDAP_UF_NORMAL_ACCOUNT ]
    ),
))
def test_parse_permissions_int(raw_user_permissions, expected):
    assert parse_permissions_int(raw_user_permissions) == expected
