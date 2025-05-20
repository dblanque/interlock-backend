
import pytest
from core.models.structs.ldap_dns_record import RecordTypes
from core.ldap.defaults import LDAP_DOMAIN
from datetime import datetime
from core.models.dns import DATE_FMT

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
		"name": "@",
		"zone": LDAP_DOMAIN,
		"ttl": 180,
		"serial": fc_record_serial_epoch(1),
	}


@pytest.fixture
def f_record_data_a(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_A.value,
		"address": "127.0.0.1",
	}


@pytest.fixture
def f_record_data_aaaa(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_AAAA.value,
		"ipv6Address": "::1",
	}


@pytest.fixture
def f_record_data_name_node(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
		"nameNode": f"subdomain.{LDAP_DOMAIN}.",
	}


@pytest.fixture
def f_record_data_string_data(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_TXT.value,
		"stringData": "example-site-verification=some_key_example",
	}


@pytest.fixture
def f_record_data_mx(f_record_data):
	return f_record_data | {
		"type": RecordTypes.DNS_RECORD_TYPE_MX.value,
		"wPreference": 10,
		"nameExchange": f"mx.{LDAP_DOMAIN}.",
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
