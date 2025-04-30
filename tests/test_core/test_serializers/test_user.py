########################### Standard Pytest Imports ############################
import pytest
################################################################################
from core.serializers.user import LDAPUserSerializer
from core.ldap.constants import (
	LDAP_ATTR_DN,
	LDAP_ATTR_USERNAME_SAMBA_ADDS,
	LDAP_ATTR_FIRST_NAME,
	LDAP_ATTR_LAST_NAME,
	LDAP_ATTR_EMAIL,
	LDAP_ATTR_POSTAL_CODE,
	LDAP_ATTR_CITY,
	LDAP_ATTR_COUNTRY,
	LDAP_ATTR_COUNTRY_DCC,
	LDAP_ATTR_COUNTRY_ISO,
	LDAP_ATTR_UPN,
	LDAP_ATTR_UAC,
	LOCAL_ATTR_USERNAME,
)
from core.ldap.adsi import (
	LDAP_UF_NORMAL_ACCOUNT,
	LDAP_UF_DONT_EXPIRE_PASSWD,
)

@pytest.mark.parametrize(
	"test_data",
	(
		{
			LDAP_ATTR_DN: "cn=testuser,dc=example,dc=com",
			LOCAL_ATTR_USERNAME: "testuser",
			LDAP_ATTR_USERNAME_SAMBA_ADDS: "testuser",
			LDAP_ATTR_EMAIL: "test@example.com",
			LDAP_ATTR_FIRST_NAME: "Test",
			LDAP_ATTR_LAST_NAME: "User",
			"permission_list": [
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_DONT_EXPIRE_PASSWD,
			],
			LDAP_ATTR_COUNTRY: "Argentina",
			LDAP_ATTR_COUNTRY_DCC: 32,
			LDAP_ATTR_COUNTRY_ISO: "AR",
			LDAP_ATTR_UAC: 66048,
		},
	),
)
def test_ldap_user_serializer_valid(test_data: dict):
	serializer = LDAPUserSerializer(data=test_data)
	assert serializer.is_valid()

@pytest.mark.parametrize(
	"key, value",
	(
		(LDAP_ATTR_DN, "cn=testuser,dc=,dc=com",),
		(LOCAL_ATTR_USERNAME, "testuser.",),
		(LOCAL_ATTR_USERNAME, "testuser/",),
		(LDAP_ATTR_USERNAME_SAMBA_ADDS, "testuser@",),
		(LDAP_ATTR_EMAIL, "test@example",),
		("permission_list", ["bad_perm_value"]),
		(LDAP_ATTR_COUNTRY, "Some Country That Does Not Exist",),
		(LDAP_ATTR_COUNTRY_DCC, 99999,),
		(LDAP_ATTR_COUNTRY_ISO, "BADCODE",),
		(LDAP_ATTR_UAC, False,),
	),
)
def test_ldap_user_serializer_raises(key, value):
	serializer = LDAPUserSerializer(data={key: value})
	assert not serializer.is_valid()
