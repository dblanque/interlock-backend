import pytest
from pytest_mock import MockType
from core.views.mixins.ldap.record import DNSRecordMixin
from core.exceptions import dns as exc_dns
from core.models.types.ldap_dns_record import RecordTypes
from core.ldap.defaults import LDAP_DOMAIN

@pytest.fixture
def f_required_values():
	return ["name", "type", "zone", "ttl"]

@pytest.fixture
def f_record_data():
	return {
		"zone": LDAP_DOMAIN,
		"ttl": 180,
	}

@pytest.fixture(autouse=True)
def f_log_mixin(mocker) -> MockType:
	mock = mocker.patch("core.views.mixins.ldap.record.DBLogMixin", mocker.MagicMock())
	return mock

@pytest.fixture
def f_record_mixin(mocker) -> DNSRecordMixin:
	mixin = DNSRecordMixin()
	mixin.ldap_connection = mocker.MagicMock()
	mixin.request = mocker.MagicMock()
	return mixin

class TestDNSRecordMixin:
	def test_validate_record_data_raises_no_type(self, f_record_mixin: DNSRecordMixin):
		with pytest.raises(exc_dns.DNSRecordTypeMissing):
			f_record_mixin.validate_record_data(record_data={})

	def test_validate_record_data_raises_root_zone_disallowed(self, f_record_mixin: DNSRecordMixin):
		with pytest.raises(exc_dns.DNSRootServersOnlyCLI):
			f_record_mixin.validate_record_data(record_data={
				"name": "@",
				"ttl": 180,
				"type": RecordTypes.DNS_RECORD_TYPE_A.value,
				"zone": "Root DNS Servers",
				"address":"127.0.0.1"
			})

	def test_validate_record_soa_root_only(self, f_record_data, f_record_mixin: DNSRecordMixin):
		with pytest.raises(exc_dns.SOARecordRootOnly):
			f_record_mixin.validate_record_data(record_data={
				"name": "subdomain",
				"type": RecordTypes.DNS_RECORD_TYPE_SOA.value,
				"dwSerialNo": 2025040701,
				"dwRefresh": 900,
				"dwRetry": 7200,
				"dwExpire": 86400,
				"dwMinimumTtl": 900,
				"namePrimaryServer": f"ldap-server.{LDAP_DOMAIN}.",
				"zoneAdminEmail": f"hostmaster.{LDAP_DOMAIN}.",
			} | f_record_data)

	def test_validate_record_string_data_len_raises(
		self,
		f_record_data,
		f_record_mixin: DNSRecordMixin,
	):
		with pytest.raises(exc_dns.DNSStringDataLimit):
			f_record_mixin.validate_record_data(record_data={
				"name": "@",
				"type": RecordTypes.DNS_RECORD_TYPE_TXT.value,
				"stringData": "a"*255,
			} | f_record_data)

	def test_validate_record_raises_on_not_canonical(
		self,
		f_record_data,
		f_record_mixin: DNSRecordMixin,
	):
		with pytest.raises(exc_dns.DNSValueNotCanonicalHostname):
			f_record_mixin.validate_record_data(record_data={
				"name": "@",
				"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				"nameNode": f"not.canonical.{LDAP_DOMAIN}",
			} | f_record_data)

	def test_validate_a_record_success(
		self,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		assert f_record_mixin.validate_record_data(
			record_data={
				"name": "@",
				"type": RecordTypes.DNS_RECORD_TYPE_A.value,
				"address": "192.168.0.1"
			} | f_record_data,
			required_values=f_required_values
		) is True

	@pytest.mark.parametrize(
		"address",
		(
			None,
			"192.168.0",
			"asd",
			False,
		),
	)
	def test_validate_a_record_error(
		self,
		address,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		with pytest.raises(exc_dns.DNSFieldValidatorFailed):
			f_record_mixin.validate_record_data(
				record_data={
					"name": "@",
					"type": RecordTypes.DNS_RECORD_TYPE_A.value,
					"address": address
				} | f_record_data,
				required_values=f_required_values
			)

	def test_validate_cname_record_success(
		self,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		assert f_record_mixin.validate_record_data(
			record_data={
				"name": "subdomain",
				"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
				"nameNode": f"subdomain2.{LDAP_DOMAIN}."
			} | f_record_data,
			required_values=f_required_values
		) is True

	def test_validate_cname_record_raises_self_reference(
		self,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		with pytest.raises(exc_dns.DNSRecordTypeConflict):
			f_record_mixin.validate_record_data(
				record_data={
					"name": "subdomain",
					"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
					"nameNode": f"subdomain.{LDAP_DOMAIN}."
				} | f_record_data,
				required_values=f_required_values
			)

	@pytest.mark.parametrize(
		"nameNode",
		(
			"example.com",
			None,
			"192.168.0",
			"192.168.0.1",
			"asd",
			False,
		),
	)
	def test_validate_cname_record_error(
		self,
		nameNode,
		f_record_mixin: DNSRecordMixin,
		f_record_data: dict,
		f_required_values
	):
		with pytest.raises(exc_dns.DNSFieldValidatorFailed):
			f_record_mixin.validate_record_data(
				record_data={
					"name": "subdomain",
					"type": RecordTypes.DNS_RECORD_TYPE_CNAME.value,
					"nameNode": nameNode
				} | f_record_data,
				required_values=f_required_values
			)

