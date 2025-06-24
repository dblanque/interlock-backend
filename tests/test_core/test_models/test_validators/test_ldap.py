import pytest
from core.models.validators.ldap import (
	ldap_uri_validator,
	record_type_validator,
)
from core.models.structs.ldap_dns_record import RecordTypes
from rest_framework.serializers import ValidationError
from core.ldap.defaults import LDAP_DOMAIN


@pytest.mark.parametrize(
	"value",
	(
		"ldap://10.10.10.1:389",
		"ldaps://192.168.0.1:636",
		f"ldap://vm-ldap.{LDAP_DOMAIN}:389",
		f"ldaps://vm-ldap.{LDAP_DOMAIN}:636",
	),
)
def test_ldap_uri_validator(value: str):
	ldap_uri_validator([value])


@pytest.mark.parametrize(
	"value",
	(
		"ldap://10.10.10.1",
		"ldaps://192.168.0.1",
		f"ldap://vm-ldap.{LDAP_DOMAIN}",
		f"ldaps://vm-ldap.{LDAP_DOMAIN}",
		"bad_value",
	),
)
def test_ldap_uri_validator_raises_exc(value: str):
	with pytest.raises(ValidationError):
		ldap_uri_validator([value])


@pytest.mark.parametrize(
	"value",
	(
		RecordTypes.DNS_RECORD_TYPE_ZERO.value,
		RecordTypes.DNS_RECORD_TYPE_A.value,
		RecordTypes.DNS_RECORD_TYPE_NS.value,
		RecordTypes.DNS_RECORD_TYPE_CNAME.value,
		RecordTypes.DNS_RECORD_TYPE_DNAME.value,
		RecordTypes.DNS_RECORD_TYPE_MB.value,
		RecordTypes.DNS_RECORD_TYPE_MR.value,
		RecordTypes.DNS_RECORD_TYPE_MG.value,
		RecordTypes.DNS_RECORD_TYPE_MD.value,
		RecordTypes.DNS_RECORD_TYPE_MF.value,
		RecordTypes.DNS_RECORD_TYPE_SOA.value,
		RecordTypes.DNS_RECORD_TYPE_TXT.value,
		RecordTypes.DNS_RECORD_TYPE_X25.value,
		RecordTypes.DNS_RECORD_TYPE_ISDN.value,
		RecordTypes.DNS_RECORD_TYPE_LOC.value,
		RecordTypes.DNS_RECORD_TYPE_HINFO.value,
		RecordTypes.DNS_RECORD_TYPE_MX.value,
		RecordTypes.DNS_RECORD_TYPE_SIG.value,
		RecordTypes.DNS_RECORD_TYPE_KEY.value,
		RecordTypes.DNS_RECORD_TYPE_AAAA.value,
		RecordTypes.DNS_RECORD_TYPE_SRV.value,
		RecordTypes.DNS_RECORD_TYPE_PTR.value,
		RecordTypes.DNS_RECORD_TYPE_WINS.value,
	),
	ids=lambda x: RecordTypes(x).name,
)
def test_record_type(value: int):
	record_type_validator(value)


@pytest.mark.parametrize(
	"value",
	(343, 117, 1701, 65535),
)
def test_record_type_raises(value: int):
	with pytest.raises(ValidationError):
		record_type_validator(value)
