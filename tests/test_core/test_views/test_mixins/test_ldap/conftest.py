
import pytest
from core.models.structs.ldap_dns_record import RecordTypes
from core.ldap.defaults import LDAP_DOMAIN
from datetime import datetime
from core.models.dns import DATE_FMT
from core.constants.dns import (
	LDNS_ATTR_ENTRY_NAME,
	LDNS_ATTR_ZONE,
	LDNS_ATTR_TTL,
	LDNS_ATTR_SERIAL,
	LDNS_ATTR_TYPE,
	LDNS_ATTR_IPV4_ADDRESS,
	LDNS_ATTR_IPV6_ADDRESS,
	LDNS_ATTR_NAME_NODE,
	LDNS_ATTR_STRING_DATA,
	LDNS_ATTR_MX_PRIORITY,
	LDNS_ATTR_MX_SERVER,
	LDNS_ATTR_SOA_SERIAL,
	LDNS_ATTR_SOA_REFRESH,
	LDNS_ATTR_SOA_RETRY,
	LDNS_ATTR_SOA_EXPIRE,
	LDNS_ATTR_SOA_MIN_TTL,
	LDNS_ATTR_SOA_PRIMARY_NS,
	LDNS_ATTR_SOA_EMAIL,
	LDNS_ATTR_SRV_PRIORITY,
	LDNS_ATTR_SRV_WEIGHT,
	LDNS_ATTR_SRV_PORT,
	LDNS_ATTR_SRV_TARGET,
)

@pytest.fixture
def fc_record_serial_epoch():
	def maker(sequence: int = 1):
		return int(
			datetime.today().strftime(DATE_FMT) + str(sequence).rjust(2, "0")
		)

	return maker


@pytest.fixture
def f_record_data(fc_record_serial_epoch):
	return {
		LDNS_ATTR_ENTRY_NAME: "@",
		LDNS_ATTR_ZONE: LDAP_DOMAIN,
		LDNS_ATTR_TTL: 180,
		LDNS_ATTR_SERIAL: fc_record_serial_epoch(1),
	}


@pytest.fixture
def f_record_data_a(f_record_data):
	return f_record_data | {
		LDNS_ATTR_TYPE: RecordTypes.DNS_RECORD_TYPE_A.value,
		LDNS_ATTR_IPV4_ADDRESS: "127.0.0.1",
	}


@pytest.fixture
def f_record_data_aaaa(f_record_data):
	return f_record_data | {
		LDNS_ATTR_TYPE: RecordTypes.DNS_RECORD_TYPE_AAAA.value,
		LDNS_ATTR_IPV6_ADDRESS: "::1",
	}


@pytest.fixture
def f_record_data_name_node(f_record_data):
	return f_record_data | {
		LDNS_ATTR_TYPE: RecordTypes.DNS_RECORD_TYPE_CNAME.value,
		LDNS_ATTR_NAME_NODE: f"subdomain.{LDAP_DOMAIN}.",
	}


@pytest.fixture
def f_record_data_string_data(f_record_data):
	return f_record_data | {
		LDNS_ATTR_TYPE: RecordTypes.DNS_RECORD_TYPE_TXT.value,
		LDNS_ATTR_STRING_DATA: "example-site-verification=some_key_example",
	}


@pytest.fixture
def f_record_data_mx(f_record_data):
	return f_record_data | {
		LDNS_ATTR_TYPE: RecordTypes.DNS_RECORD_TYPE_MX.value,
		LDNS_ATTR_MX_PRIORITY: 10,
		LDNS_ATTR_MX_SERVER: f"mx.{LDAP_DOMAIN}.",
	}


@pytest.fixture
def f_record_data_soa(f_record_data):
	return f_record_data | {
		LDNS_ATTR_TYPE: RecordTypes.DNS_RECORD_TYPE_SOA.value,
		LDNS_ATTR_SOA_SERIAL: 1,
		LDNS_ATTR_SOA_REFRESH: 900,
		LDNS_ATTR_SOA_RETRY: 600,
		LDNS_ATTR_SOA_EXPIRE: 86400,
		LDNS_ATTR_SOA_MIN_TTL: 900,
		LDNS_ATTR_SOA_PRIMARY_NS: f"ns.{LDAP_DOMAIN}.",
		LDNS_ATTR_SOA_EMAIL: f"hostmaster.{LDAP_DOMAIN}.",
	}


@pytest.fixture
def f_record_data_srv(f_record_data):
	return f_record_data | {
		LDNS_ATTR_TYPE: RecordTypes.DNS_RECORD_TYPE_SRV.value,
		LDNS_ATTR_SRV_PRIORITY: 0,
		LDNS_ATTR_SRV_WEIGHT: 5,
		LDNS_ATTR_SRV_PORT: 22,
		LDNS_ATTR_SRV_TARGET: f"_ssh._tcp.{LDAP_DOMAIN}.",
	}
