import pytest
from pytest_mock import MockType
from core.views.mixins.ldap.record import DNSRecordMixin
from rest_framework.exceptions import ValidationError
from core.serializers.record import (
	DNSRecordAAAASerializer,
	DNSRecordASerializer,
	DNSRecordMXSerializer,
	DNSRecordNameNodeSerializer,
	DNSRecordSOASerializer,
	DNSRecordSRVSerializer,
	DNSRecordStringDataSerializer,
)
from core.exceptions import dns as exc_dns
from core.models.structs.ldap_dns_record import RecordTypes
from core.ldap.defaults import LDAP_DOMAIN

MODULE_PATH = "core.views.mixins.ldap.record"
@pytest.fixture
def f_record_mixin():
	return DNSRecordMixin()

@pytest.fixture(autouse=True)
def f_logger(mocker):
	return mocker.patch(f"{MODULE_PATH}.logger")

@pytest.fixture
def f_record_data():
	return {
		"name": "@",
		"zone": LDAP_DOMAIN,
		"ttl": 180,
	}

@pytest.fixture
def f_record_data_a(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_A.value,
		"address":"127.0.0.1"
	}

@pytest.fixture
def f_record_data_aaaa(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_AAAA.value,
		"ipv6Address":"::1"
	}

@pytest.fixture
def f_record_data_name_node(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
		"nameNode":f"subdomain.{LDAP_DOMAIN}."
	}

@pytest.fixture
def f_record_data_string_data(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_TXT.value,
		"stringData": "example-site-verification=some_key_example"
	}

@pytest.fixture
def f_record_data_mx(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_MX.value,
		"wPreference": 10,
		"nameExchange": f"mx.{LDAP_DOMAIN}."
	}

@pytest.fixture
def f_record_data_soa(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_SOA.value,
		"dwSerialNo": 1,
		"dwRefresh": 900,
		"dwRetry": 600,
		"dwExpire": 86400,
		"dwMinimumTtl": 900,
		"namePrimaryServer": f"ns.{LDAP_DOMAIN}.",
		"zoneAdminEmail": f"hostmaster.{LDAP_DOMAIN}.",
	}

@pytest.fixture
def f_record_data_srv(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_SRV.value,
		"wPriority": 0,
		"wWeight": 5,
		"wPort": 22,
		"nameTarget": f"_ssh._tcp.{LDAP_DOMAIN}.",
	}


@pytest.mark.parametrize(
	"record_types, expected_serializer_cls",
	(
		# A Struct
		(
			(RecordTypes.DNS_RECORD_TYPE_A,),
			DNSRecordASerializer,
		),
		# AAAA Struct
		(
			(RecordTypes.DNS_RECORD_TYPE_AAAA,),
			DNSRecordAAAASerializer,
		),
		# NameNode Structs
		(
			(
				RecordTypes.DNS_RECORD_TYPE_NS,
				RecordTypes.DNS_RECORD_TYPE_CNAME,
				RecordTypes.DNS_RECORD_TYPE_DNAME,
				RecordTypes.DNS_RECORD_TYPE_PTR,
			),
			DNSRecordNameNodeSerializer,
		),
		# String Data Structs
		(
			(
				RecordTypes.DNS_RECORD_TYPE_TXT,
				RecordTypes.DNS_RECORD_TYPE_X25,
				RecordTypes.DNS_RECORD_TYPE_ISDN,
				RecordTypes.DNS_RECORD_TYPE_LOC,
				RecordTypes.DNS_RECORD_TYPE_HINFO,
			),
			DNSRecordStringDataSerializer,	
		),
		# MX Struct
		(
			(RecordTypes.DNS_RECORD_TYPE_MX,),
			DNSRecordMXSerializer,
		),
		# SOA Struct
		(
			(RecordTypes.DNS_RECORD_TYPE_SOA,),
			DNSRecordSOASerializer,
		),
		# SRV Struct
		(
			(RecordTypes.DNS_RECORD_TYPE_SRV,),
			DNSRecordSRVSerializer,
		),
	),
)
def test_get_serializer(
	f_record_mixin: DNSRecordMixin,
	record_types: tuple[RecordTypes],
	expected_serializer_cls,
):
	for _type in record_types:
		assert f_record_mixin.get_serializer(_type.value) == expected_serializer_cls

def test_get_serializer_raises_missing_type(f_record_mixin: DNSRecordMixin):
	with pytest.raises(exc_dns.DNSRecordTypeMissing):
		f_record_mixin.get_serializer(False)
	with pytest.raises(exc_dns.DNSRecordTypeMissing):
		f_record_mixin.get_serializer(None)

@pytest.mark.parametrize(
	"bad_record_type",
	(
		1179,
		64890,
		"some_string",
		b"some_bytes",
		["some","list"],
	),
)
def test_get_serializer_raises_validation_error(
	bad_record_type,
	f_record_mixin: DNSRecordMixin
):
	with pytest.raises(ValidationError):
		f_record_mixin.get_serializer(bad_record_type)

@pytest.mark.parametrize(
	"record_types, record_fixture",
	(
		# A Struct
		(
			(RecordTypes.DNS_RECORD_TYPE_A,),
			"f_record_data_a",
		),
		# AAAA Struct
		(
			(RecordTypes.DNS_RECORD_TYPE_AAAA,),
			"f_record_data_aaaa",
		),
		# NameNode Structs
		(
			(
				RecordTypes.DNS_RECORD_TYPE_NS,
				RecordTypes.DNS_RECORD_TYPE_CNAME,
				RecordTypes.DNS_RECORD_TYPE_DNAME,
				RecordTypes.DNS_RECORD_TYPE_PTR,
			),
			"f_record_data_name_node",
		),
		# String Data Structs
		(
			(
				RecordTypes.DNS_RECORD_TYPE_TXT,
				RecordTypes.DNS_RECORD_TYPE_X25,
				RecordTypes.DNS_RECORD_TYPE_ISDN,
				RecordTypes.DNS_RECORD_TYPE_LOC,
				RecordTypes.DNS_RECORD_TYPE_HINFO,
			),
			"f_record_data_string_data",	
		),
		# MX Struct
		(
			(RecordTypes.DNS_RECORD_TYPE_MX,),
			"f_record_data_mx",
		),
		# SOA Struct
		(
			(RecordTypes.DNS_RECORD_TYPE_SOA,),
			"f_record_data_soa",
		),
		# SRV Struct
		(
			(RecordTypes.DNS_RECORD_TYPE_SRV,),
			"f_record_data_srv",
		),
	),
)
def test_validate_record(f_logger, record_types: list[RecordTypes], record_fixture: str, request, f_record_mixin: DNSRecordMixin):
	for _type in record_types:
		m_record_data = request.getfixturevalue(record_fixture)
		m_record_data["type"] = _type.value
		m_record_data["unknown_key"] = "some_weird_value"
		f_record_mixin.validate_record(record_data=m_record_data)
	f_logger.info.call_count == len(record_types)

def test_validate_record_raises_soa_not_root(f_record_data_soa: dict, f_record_mixin: DNSRecordMixin):
	f_record_data_soa["name"] = "subdomain"
	f_record_data_soa["type"] = RecordTypes.DNS_RECORD_TYPE_SOA.value
	with pytest.raises(exc_dns.SOARecordRootOnly):
		f_record_mixin.validate_record(record_data=f_record_data_soa)

@pytest.mark.parametrize(
	"bad_zone",
	(
		"Root DNS Servers",
		"root dns servers",
		"@",
		".",
		"root.",
	),
)
def test_validate_record_raises_root_dns_servers_validation_error(
	bad_zone: str,
	f_record_data_soa: dict,
	f_record_mixin: DNSRecordMixin
):
	f_record_data_soa["zone"] = bad_zone
	with pytest.raises(ValidationError):
		f_record_mixin.validate_record(record_data=f_record_data_soa)

@pytest.mark.parametrize(
	"bad_zone",
	(
		"Root DNS Servers",
		"root dns servers",
		"@",
		".",
		"root.",
	),
)
def test_validate_record_raises_root_dns_servers_validation_error(
	bad_zone: str,
	mocker,
	f_record_data_soa: dict,
	f_record_mixin: DNSRecordMixin
):
	m_serializer = mocker.MagicMock()
	m_serializer.is_valid.return_value = None
	m_serializer.initial_data = f_record_data_soa
	m_serializer.fields = f_record_data_soa
	mocker.patch.object(f_record_mixin, "get_serializer", return_value=m_serializer)
	f_record_data_soa["zone"] = bad_zone
	with pytest.raises(exc_dns.DNSRootServersOnlyCLI):
		f_record_mixin.validate_record(record_data=f_record_data_soa)

def test_validate_record_raises_on_self_reference(
	f_record_data_name_node: dict,
	f_record_mixin: DNSRecordMixin
):
	f_record_data_name_node["name"] = f"subdomain"
	f_record_data_name_node["nameNode"] = f"subdomain.{LDAP_DOMAIN}."
	with pytest.raises(exc_dns.DNSRecordSelfReference):
		f_record_mixin.validate_record(record_data=f_record_data_name_node)

def test_validate_record_does_not_raise_self_reference(
	f_record_data_name_node: dict,
	f_record_mixin: DNSRecordMixin
):
	f_record_data_name_node["name"] = f"subdomain"
	f_record_data_name_node["nameNode"] = f"subdomain.sub2.{LDAP_DOMAIN}."
	f_record_mixin.validate_record(record_data=f_record_data_name_node)

def test_create_record():
	pass

def test_update_record():
	pass

def test_delete_record():
	pass