import pytest
from core.ldap.defaults import LDAP_AUTH_SEARCH_BASE, LDAP_DOMAIN
from core.models.dns import LDAPDNS, SerialGenerator, DATE_FMT
from datetime import datetime
from pytest_mock import MockType


@pytest.fixture
def f_runtime_settings(mocker):
	m_runtime_settings = mocker.Mock()
	m_runtime_settings.LDAP_AUTH_SEARCH_BASE = LDAP_AUTH_SEARCH_BASE
	return mocker.patch("core.models.dns.RuntimeSettings", m_runtime_settings)


@pytest.mark.django_db
class TestLDAPDNS:
	@pytest.mark.parametrize(
		"legacy_dns, expected_dns_root",
		(
			(True, f"CN=MicrosoftDNS,CN=System,{LDAP_AUTH_SEARCH_BASE}"),
			(False, f"CN=MicrosoftDNS,DC=DomainDnsZones,{LDAP_AUTH_SEARCH_BASE}"),
		),
		ids=["Legacy LDAP DNS", "Standard LDAP DNS"],
	)
	def test_init(self, mocker, legacy_dns, expected_dns_root, f_runtime_settings):
		m_connection = mocker.MagicMock()
		f_runtime_settings.LDAP_DNS_LEGACY = legacy_dns
		m_list_dns_zones: MockType = mocker.patch.object(
			LDAPDNS, "list_dns_zones", return_value=None
		)
		m_list_forest_zones: MockType = mocker.patch.object(
			LDAPDNS, "list_forest_zones", return_value=None
		)
		ldap_dns = LDAPDNS(m_connection)

		assert ldap_dns.dnsroot == expected_dns_root
		assert ldap_dns.forestroot == f"CN=MicrosoftDNS,DC=ForestDnsZones,{LDAP_AUTH_SEARCH_BASE}"
		m_list_dns_zones.assert_called_once()
		m_list_forest_zones.assert_called_once()

	def test_list_dns_zones(self, mocker, f_runtime_settings):
		m_connection = mocker.MagicMock()
		mocker.patch("core.models.dns.dnstool.get_dns_zones", return_value=[LDAP_DOMAIN])
		mocker.patch.object(LDAPDNS, "list_forest_zones", return_value=None)
		ldap_dns = LDAPDNS(m_connection)
		assert ldap_dns.dnszones == [LDAP_DOMAIN]

	def test_list_forest_zones(self, mocker, f_runtime_settings):
		m_connection = mocker.MagicMock()
		mocker.patch(
			"core.models.dns.dnstool.get_dns_zones", return_value=[f"_msdcs.{LDAP_DOMAIN}"]
		)
		mocker.patch.object(LDAPDNS, "list_dns_zones", return_value=None)
		ldap_dns = LDAPDNS(m_connection)
		assert ldap_dns.forestzones == [f"_msdcs.{LDAP_DOMAIN}"]


class TestSerialGenerator:
	DT_TODAY = datetime.today()
	DT_TODAY_STR = DT_TODAY.strftime(DATE_FMT)

	def test_serial_is_epoch_datetime_raise_type_error(self):
		with pytest.raises(TypeError, match="must be an int"):
			SerialGenerator.serial_as_datetime("a")

	def test_serial_is_epoch_datetime_false(self):
		assert SerialGenerator.serial_as_datetime(1) is False

	def test_serial_is_epoch_datetime(self):
		assert SerialGenerator.serial_as_datetime(2024010121) == datetime.strptime(
			"20240101", DATE_FMT
		)

	@pytest.mark.parametrize(
		"old_serial, new_serial",
		(
			(  # (int) Different day, restart serial
				2024010121,
				int(f"{DT_TODAY_STR}01"),
			),
			(  # (str) Different day, restart serial
				"2024010121",
				int(f"{DT_TODAY_STR}01"),
			),
			(  # (int) Same day, increase serial
				int(f"{DT_TODAY_STR}01"),
				int(f"{DT_TODAY_STR}02"),
			),
			(  # (int) Same day, restart serial
				int(f"{DT_TODAY_STR}99"),
				int(f"{DT_TODAY_STR}01"),
			),
		),
		ids=[
			"(int) Different day, restart serial",
			"(str) Different day, restart serial",
			"(int) Same day, increase serial",
			"(int) Same day, restart serial",
		],
	)
	def test_generate_epoch(self, old_serial, new_serial):
		old_serial_obj = datetime.strptime(str(old_serial)[:8], DATE_FMT)
		generated_serial = SerialGenerator.generate_epoch(old_serial, old_serial_obj)
		assert generated_serial == new_serial

	@pytest.mark.parametrize(
		"serial, serial_date_obj, expected",
		((b"2024010121", None, "of type int or str"), (20240101_01, None, "of type datetime")),
		ids=[
			"serial not int or str raises TypeError",
			"serial_date_obj not datetime raises TypeError",
		],
	)
	def test_generate_epoch_raises_type_error(self, serial, serial_date_obj, expected):
		with pytest.raises(TypeError, match=expected):
			SerialGenerator.generate_epoch(serial, serial_date_obj)
