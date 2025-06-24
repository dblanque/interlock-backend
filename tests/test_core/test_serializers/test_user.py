########################### Standard Pytest Imports ############################
import pytest

################################################################################
from core.serializers.user import LDAPUserSerializer, UserSerializer
from rest_framework.serializers import ValidationError
from core.constants.attrs import *
from core.ldap.adsi import (
	LDAP_UF_NORMAL_ACCOUNT,
	LDAP_UF_DONT_EXPIRE_PASSWD,
)


@pytest.mark.django_db
def test_validate_password_confirm():
	serializer = UserSerializer(
		data={LOCAL_ATTR_PASSWORD: "a", LOCAL_ATTR_PASSWORD_CONFIRM: "a"},
		partial=True,
	)
	assert serializer.is_valid()


@pytest.mark.django_db
def test_validate_password_confirm_raises_password_mismatch():
	serializer = UserSerializer(
		data={LOCAL_ATTR_PASSWORD: "a", LOCAL_ATTR_PASSWORD_CONFIRM: "b"},
		partial=True,
	)
	with pytest.raises(ValidationError) as e:
		serializer.is_valid(raise_exception=True)
	assert e.value.detail.get(LOCAL_ATTR_PASSWORD_CONFIRM)


@pytest.mark.django_db
def test_validate_password_confirm_raises_field_missing():
	serializer = UserSerializer(
		data={
			LOCAL_ATTR_PASSWORD: "a",
		},
		partial=True,
	)
	with pytest.raises(ValidationError) as e:
		serializer.is_valid(raise_exception=True)
	assert e.value.detail.get(LOCAL_ATTR_PASSWORD_CONFIRM)


@pytest.mark.parametrize(
	"test_data",
	(
		{
			LOCAL_ATTR_DN: "cn=testuser,dc=example,dc=com",
			LOCAL_ATTR_USERNAME: "testuser",
			LOCAL_ATTR_EMAIL: "test@example.com",
			LOCAL_ATTR_FIRST_NAME: "Test",
			LOCAL_ATTR_LAST_NAME: "User",
			LOCAL_ATTR_PERMISSIONS: [
				LDAP_UF_NORMAL_ACCOUNT,
				LDAP_UF_DONT_EXPIRE_PASSWD,
			],
			LOCAL_ATTR_COUNTRY: "Argentina",
			LOCAL_ATTR_COUNTRY_DCC: 32,
			LOCAL_ATTR_COUNTRY_ISO: "AR",
			LOCAL_ATTR_UAC: 66048,
		},
	),
)
def test_ldap_user_serializer_valid(test_data: dict):
	serializer = LDAPUserSerializer(data=test_data)
	assert serializer.is_valid()


@pytest.mark.parametrize(
	"key, value",
	(
		(
			LOCAL_ATTR_DN,
			"cn=testuser,dc=,dc=com",
		),
		(
			LOCAL_ATTR_USERNAME,
			"testuser.",
		),
		(
			LOCAL_ATTR_USERNAME,
			"testuser/",
		),
		(
			LOCAL_ATTR_USERNAME,
			"testuser@",
		),
		(
			LOCAL_ATTR_EMAIL,
			"test@example",
		),
		(LOCAL_ATTR_PERMISSIONS, ["bad_perm_value"]),
		(
			LOCAL_ATTR_COUNTRY,
			"Some Country That Does Not Exist",
		),
		(
			LOCAL_ATTR_COUNTRY_DCC,
			99999,
		),
		(
			LOCAL_ATTR_COUNTRY_ISO,
			"BADCODE",
		),
		(
			LOCAL_ATTR_UAC,
			False,
		),
	),
)
def test_ldap_user_serializer_raises(key, value):
	serializer = LDAPUserSerializer(data={key: value})
	assert not serializer.is_valid()
