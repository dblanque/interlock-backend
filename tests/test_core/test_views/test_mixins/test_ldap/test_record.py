import pytest
from pytest_mock import MockType, MockerFixture
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
from core.views.mixins.logs import LogMixin
from core.exceptions import (
	dns as exc_dns,
	base as exc_base,
	ldap as exc_ldap,
)
from core.models.structs.ldap_dns_record import RecordTypes
from core.ldap.defaults import LDAP_DOMAIN
from core.models.choices.log import (
	LOG_ACTION_CREATE,
	LOG_ACTION_UPDATE,
	LOG_ACTION_DELETE,
	LOG_CLASS_DNSR,
)
from datetime import datetime
from core.models.dns import record_type_main_field


@pytest.fixture
def f_record_mixin(mocker: MockerFixture):
	m_mixin = DNSRecordMixin()
	m_mixin.ldap_connection = mocker.MagicMock()
	return m_mixin


@pytest.fixture(autouse=True)
def f_logger(mocker):
	return mocker.patch("core.views.mixins.ldap.record.logger")


@pytest.fixture(autouse=True)
def f_log_mixin(mocker):
	return mocker.patch(
		f"core.views.mixins.ldap.record.DBLogMixin", mocker.MagicMock()
	)


@pytest.fixture
def fc_record_serial_epoch():
	def maker(sequence: int = 1):
		return int(
			datetime.today().strftime("%Y%m%d") + str(sequence).rjust(2, "0")
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


def get_record_fixture_name(record_type: RecordTypes | int):
	if isinstance(record_type, int):
		record_type = RecordTypes(record_type)

	if record_type in (RecordTypes.DNS_RECORD_TYPE_A,):
		return "f_record_data_a"
	elif record_type in (RecordTypes.DNS_RECORD_TYPE_AAAA,):
		return "f_record_data_aaaa"
	elif record_type in (
		RecordTypes.DNS_RECORD_TYPE_NS,
		RecordTypes.DNS_RECORD_TYPE_CNAME,
		RecordTypes.DNS_RECORD_TYPE_DNAME,
		RecordTypes.DNS_RECORD_TYPE_PTR,
	):
		return "f_record_data_name_node"
	elif record_type in (
		RecordTypes.DNS_RECORD_TYPE_TXT,
		RecordTypes.DNS_RECORD_TYPE_X25,
		RecordTypes.DNS_RECORD_TYPE_ISDN,
		RecordTypes.DNS_RECORD_TYPE_LOC,
		RecordTypes.DNS_RECORD_TYPE_HINFO,
	):
		return "f_record_data_string_data"
	elif record_type in (RecordTypes.DNS_RECORD_TYPE_SOA,):
		return "f_record_data_soa"
	elif record_type in (RecordTypes.DNS_RECORD_TYPE_MX,):
		return "f_record_data_mx"
	elif record_type in (RecordTypes.DNS_RECORD_TYPE_SRV,):
		return "f_record_data_srv"
	raise ValueError(f"Could not fetch fixture for {record_type.name}")


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
		assert (
			f_record_mixin.get_serializer(_type.value)
			== expected_serializer_cls
		)


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
		["some", "list"],
	),
)
def test_get_serializer_raises_validation_error(
	bad_record_type, f_record_mixin: DNSRecordMixin
):
	with pytest.raises(ValidationError):
		f_record_mixin.get_serializer(bad_record_type)


@pytest.mark.parametrize(
	"record_type",
	(
		RecordTypes.DNS_RECORD_TYPE_A,
		RecordTypes.DNS_RECORD_TYPE_AAAA,
		RecordTypes.DNS_RECORD_TYPE_NS,
		RecordTypes.DNS_RECORD_TYPE_CNAME,
		RecordTypes.DNS_RECORD_TYPE_DNAME,
		RecordTypes.DNS_RECORD_TYPE_PTR,
		RecordTypes.DNS_RECORD_TYPE_TXT,
		RecordTypes.DNS_RECORD_TYPE_X25,
		RecordTypes.DNS_RECORD_TYPE_ISDN,
		RecordTypes.DNS_RECORD_TYPE_LOC,
		RecordTypes.DNS_RECORD_TYPE_HINFO,
		RecordTypes.DNS_RECORD_TYPE_SOA,
		RecordTypes.DNS_RECORD_TYPE_MX,
		RecordTypes.DNS_RECORD_TYPE_SRV,
	),
)
def test_validate_record(
	f_logger, record_type: RecordTypes, request, f_record_mixin: DNSRecordMixin
):
	m_record_data = request.getfixturevalue(
		get_record_fixture_name(record_type)
	)
	m_record_data["type"] = record_type.value
	m_record_data["unknown_key"] = "some_weird_value"
	f_record_mixin.validate_record(record_data=m_record_data)
	f_logger.info.assert_called_once()


def test_validate_record_raises_soa_not_root(
	f_record_data_soa: dict, f_record_mixin: DNSRecordMixin
):
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
	bad_zone: str, f_record_data_soa: dict, f_record_mixin: DNSRecordMixin
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
	f_record_mixin: DNSRecordMixin,
):
	m_serializer = mocker.MagicMock()
	m_serializer.is_valid.return_value = None
	m_serializer.initial_data = f_record_data_soa
	m_serializer.fields = f_record_data_soa
	mocker.patch.object(
		f_record_mixin, "get_serializer", return_value=m_serializer
	)
	f_record_data_soa["zone"] = bad_zone
	with pytest.raises(exc_dns.DNSRootServersOnlyCLI):
		f_record_mixin.validate_record(record_data=f_record_data_soa)


def test_validate_record_raises_on_self_reference(
	f_record_data_name_node: dict, f_record_mixin: DNSRecordMixin
):
	f_record_data_name_node["name"] = f"subdomain"
	f_record_data_name_node["nameNode"] = f"subdomain.{LDAP_DOMAIN}."
	with pytest.raises(exc_dns.DNSRecordSelfReference):
		f_record_mixin.validate_record(record_data=f_record_data_name_node)


def test_validate_record_does_not_raise_self_reference(
	f_record_data_name_node: dict, f_record_mixin: DNSRecordMixin
):
	f_record_data_name_node["name"] = f"subdomain"
	f_record_data_name_node["nameNode"] = f"subdomain.sub2.{LDAP_DOMAIN}."
	f_record_mixin.validate_record(record_data=f_record_data_name_node)


def test_create_raises_no_connection(f_record_mixin: DNSRecordMixin):
	f_record_mixin.ldap_connection = None
	with pytest.raises(exc_ldap.LDAPConnectionNotOpen):
		f_record_mixin.create_record(record_data={})


@pytest.mark.parametrize(
	"record_type",
	(
		RecordTypes.DNS_RECORD_TYPE_A.value,
		RecordTypes.DNS_RECORD_TYPE_AAAA.value,
		RecordTypes.DNS_RECORD_TYPE_NS.value,
		RecordTypes.DNS_RECORD_TYPE_CNAME.value,
		RecordTypes.DNS_RECORD_TYPE_DNAME.value,
		RecordTypes.DNS_RECORD_TYPE_PTR.value,
		RecordTypes.DNS_RECORD_TYPE_TXT.value,
		RecordTypes.DNS_RECORD_TYPE_X25.value,
		RecordTypes.DNS_RECORD_TYPE_ISDN.value,
		RecordTypes.DNS_RECORD_TYPE_LOC.value,
		RecordTypes.DNS_RECORD_TYPE_HINFO.value,
		RecordTypes.DNS_RECORD_TYPE_SOA.value,
		RecordTypes.DNS_RECORD_TYPE_MX.value,
		RecordTypes.DNS_RECORD_TYPE_SRV.value,
	),
	ids=lambda t: RecordTypes(t).name,
)
def test_create_record(
	mocker: MockerFixture,
	record_type: int,
	request: pytest.FixtureRequest,
	f_record_mixin: DNSRecordMixin,
	f_log_mixin: LogMixin,
):
	record_fixture = request.getfixturevalue(
		get_record_fixture_name(record_type)
	)
	record_fixture["type"] = record_type
	record_main_value = record_fixture[
		record_type_main_field(record_fixture["type"])
	]
	m_request = mocker.MagicMock()
	m_request.user.id = 1
	f_record_mixin.request = m_request
	m_increment_serial: MockType = mocker.patch.object(
		f_record_mixin, "increment_soa_serial"
	)
	m_ldap_record_instance = mocker.MagicMock()
	m_ldap_record = mocker.patch(
		f"core.views.mixins.ldap.record.LDAPRecord",
		return_value=m_ldap_record_instance,
	)
	m_soa_object = mocker.MagicMock()
	m_create: MockType = mocker.MagicMock()
	m_ldap_record_instance.create = m_create
	m_ldap_record_instance.soa_object = m_soa_object
	m_ldap_record_instance.as_dict = record_fixture
	m_ldap_record_instance.__fullname__ = mocker.Mock(
		return_value="mock_fullname"
	)

	result = f_record_mixin.create_record(record_data=record_fixture)
	m_ldap_record.assert_called_once_with(
		connection=f_record_mixin.ldap_connection,
		record_name=record_fixture["name"],
		record_zone=record_fixture["zone"],
		record_type=record_type,
		record_main_value=record_main_value,
	)
	m_create.assert_called_once_with(values=record_fixture)

	if record_type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
		m_increment_serial.assert_not_called()
	else:
		m_increment_serial.assert_called_once_with(
			m_ldap_record_instance.soa_object, m_ldap_record_instance.serial
		)

	f_log_mixin.log.assert_any_call(
		user=1,
		operation_type=LOG_ACTION_CREATE,
		log_target_class=LOG_CLASS_DNSR,
		log_target="mock_fullname",
	)
	assert isinstance(result, dict)


def test_create_record_raises_could_not_increment_soa(
	mocker: MockerFixture,
	f_record_data_a,
	f_record_mixin: DNSRecordMixin,
	f_log_mixin: LogMixin,
):
	record_fixture = f_record_data_a
	record_fixture["type"] = RecordTypes.DNS_RECORD_TYPE_A.value
	m_request = mocker.MagicMock()
	m_request.user.id = 1
	f_record_mixin.request = m_request
	mocker.patch.object(
		f_record_mixin, "increment_soa_serial", side_effect=Exception
	)
	m_ldap_record_instance = mocker.MagicMock()
	mocker.patch(
		f"core.views.mixins.ldap.record.LDAPRecord",
		return_value=m_ldap_record_instance,
	)
	m_soa_object = mocker.MagicMock()
	m_create: MockType = mocker.MagicMock()
	m_ldap_record_instance.create = m_create
	m_ldap_record_instance.soa_object = m_soa_object
	m_ldap_record_instance.as_dict = record_fixture
	m_ldap_record_instance.__fullname__ = mocker.Mock(
		return_value="mock_fullname"
	)

	with pytest.raises(exc_dns.DNSCouldNotIncrementSOA):
		f_record_mixin.create_record(record_data=record_fixture)


def test_update_raises_no_connection(f_record_mixin: DNSRecordMixin):
	f_record_mixin.ldap_connection = None
	with pytest.raises(exc_ldap.LDAPConnectionNotOpen):
		f_record_mixin.update_record(record_data={}, old_record_data={})


@pytest.mark.parametrize(
	"record_type",
	(
		RecordTypes.DNS_RECORD_TYPE_A.value,
		RecordTypes.DNS_RECORD_TYPE_AAAA.value,
		RecordTypes.DNS_RECORD_TYPE_NS.value,
		RecordTypes.DNS_RECORD_TYPE_CNAME.value,
		RecordTypes.DNS_RECORD_TYPE_DNAME.value,
		RecordTypes.DNS_RECORD_TYPE_PTR.value,
		RecordTypes.DNS_RECORD_TYPE_TXT.value,
		RecordTypes.DNS_RECORD_TYPE_X25.value,
		RecordTypes.DNS_RECORD_TYPE_ISDN.value,
		RecordTypes.DNS_RECORD_TYPE_LOC.value,
		RecordTypes.DNS_RECORD_TYPE_HINFO.value,
		RecordTypes.DNS_RECORD_TYPE_SOA.value,
		RecordTypes.DNS_RECORD_TYPE_MX.value,
		RecordTypes.DNS_RECORD_TYPE_SRV.value,
	),
	ids=lambda t: RecordTypes(t).name,
)
def test_update_record_same_name(
	mocker: MockerFixture,
	record_type: int,
	f_record_mixin: DNSRecordMixin,
	request: pytest.FixtureRequest,
	f_log_mixin: LogMixin,
):
	record_fixture_name = get_record_fixture_name(record_type)
	record_fixture: dict = request.getfixturevalue(record_fixture_name)
	record_fixture["type"] = record_type
	record_main_field = record_type_main_field(record_type)
	old_record_data = record_fixture.copy()
	record_data = record_fixture.copy()
	old_record_data[record_main_field] = "old_value"
	record_data[record_main_field] = "new_value"

	m_request = mocker.MagicMock()
	m_request.user.id = 1
	f_record_mixin.request = m_request
	m_increment_serial: MockType = mocker.patch.object(
		f_record_mixin, "increment_soa_serial"
	)
	m_ldap_record_instance = mocker.MagicMock()
	m_soa_object = mocker.MagicMock()
	m_ldap_record_instance.soa_object = m_soa_object
	m_ldap_record_instance.as_dict = record_data
	m_ldap_record_instance.__fullname__ = mocker.Mock(
		return_value="mock_fullname"
	)
	m_ldap_record = mocker.patch(
		f"core.views.mixins.ldap.record.LDAPRecord",
		return_value=m_ldap_record_instance,
	)

	result = f_record_mixin.update_record(
		record_data=record_data, old_record_data=old_record_data
	)
	m_ldap_record.assert_called_once_with(
		connection=f_record_mixin.ldap_connection,
		record_name=record_fixture["name"],
		record_zone=record_fixture["zone"],
		record_type=record_type,
		record_main_value=record_data[record_main_field],
	)
	m_ldap_record_instance.update.assert_called_once_with(
		new_values=record_data, old_values=old_record_data
	)

	if record_type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
		m_increment_serial.assert_not_called()
	else:
		m_increment_serial.assert_called_once_with(
			m_ldap_record_instance.soa_object, m_ldap_record_instance.serial
		)

	f_log_mixin.log.assert_any_call(
		user=1,
		operation_type=LOG_ACTION_UPDATE,
		log_target_class=LOG_CLASS_DNSR,
		log_target="mock_fullname",
	)
	assert isinstance(result, dict)


@pytest.mark.parametrize(
	"record_type",
	(
		RecordTypes.DNS_RECORD_TYPE_A.value,
		RecordTypes.DNS_RECORD_TYPE_AAAA.value,
		RecordTypes.DNS_RECORD_TYPE_NS.value,
		RecordTypes.DNS_RECORD_TYPE_CNAME.value,
		RecordTypes.DNS_RECORD_TYPE_DNAME.value,
		RecordTypes.DNS_RECORD_TYPE_PTR.value,
		RecordTypes.DNS_RECORD_TYPE_TXT.value,
		RecordTypes.DNS_RECORD_TYPE_X25.value,
		RecordTypes.DNS_RECORD_TYPE_ISDN.value,
		RecordTypes.DNS_RECORD_TYPE_LOC.value,
		RecordTypes.DNS_RECORD_TYPE_HINFO.value,
		RecordTypes.DNS_RECORD_TYPE_SOA.value,
		RecordTypes.DNS_RECORD_TYPE_MX.value,
		RecordTypes.DNS_RECORD_TYPE_SRV.value,
	),
	ids=lambda t: RecordTypes(t).name,
)
def test_update_record_different_name(
	mocker: MockerFixture,
	record_type: int,
	f_record_mixin: DNSRecordMixin,
	request: pytest.FixtureRequest,
	f_log_mixin: LogMixin,
):
	record_fixture_name = get_record_fixture_name(record_type)
	record_fixture: dict = request.getfixturevalue(record_fixture_name)
	record_fixture["type"] = record_type
	record_main_field = record_type_main_field(record_type)
	old_record_data = record_fixture.copy()
	record_data = record_fixture.copy()
	old_record_data["name"] = "subdomain1"
	record_data["name"] = "subdomain2"
	old_record_data[record_main_field] = "old_value"
	record_data[record_main_field] = "new_value"

	m_request = mocker.MagicMock()
	m_request.user.id = 1
	f_record_mixin.request = m_request
	m_increment_serial: MockType = mocker.patch.object(
		f_record_mixin, "increment_soa_serial"
	)
	m_ldap_record_instance = mocker.MagicMock()
	m_old_ldap_record_instance = mocker.MagicMock()
	m_soa_object = mocker.MagicMock()
	m_ldap_record_instance.create.return_value = {"result": 0}
	m_ldap_record_instance.soa_object = m_soa_object
	m_ldap_record_instance.as_dict = record_data
	m_ldap_record_instance.__fullname__ = mocker.Mock(
		return_value="mock_fullname"
	)
	m_ldap_record = mocker.patch(
		f"core.views.mixins.ldap.record.LDAPRecord",
		side_effect=[m_ldap_record_instance, m_old_ldap_record_instance],
	)

	result = f_record_mixin.update_record(
		record_data=record_data, old_record_data=old_record_data
	)
	m_ldap_record.assert_any_call(
		connection=f_record_mixin.ldap_connection,
		record_name=record_data["name"],
		record_zone=record_data["zone"],
		record_type=record_type,
		record_main_value=record_data[record_main_field],
	)
	m_ldap_record.assert_any_call(
		connection=f_record_mixin.ldap_connection,
		record_name=old_record_data["name"],
		record_zone=old_record_data["zone"],
		record_type=record_type,
		record_main_value=old_record_data[record_main_field],
	)
	assert m_ldap_record.call_count == 2
	m_ldap_record_instance.create.assert_called_once_with(values=record_data)
	m_old_ldap_record_instance.delete.assert_called_once()
	m_ldap_record_instance.update.assert_not_called()

	if record_type == RecordTypes.DNS_RECORD_TYPE_SOA.value:
		m_increment_serial.assert_not_called()
	else:
		m_increment_serial.assert_called_once_with(
			m_ldap_record_instance.soa_object, m_ldap_record_instance.serial
		)

	f_log_mixin.log.assert_any_call(
		user=1,
		operation_type=LOG_ACTION_UPDATE,
		log_target_class=LOG_CLASS_DNSR,
		log_target="mock_fullname",
	)
	assert isinstance(result, dict)


def test_update_record_raises_increment_soa_exception(
	mocker: MockerFixture,
	f_record_mixin: DNSRecordMixin,
	request: pytest.FixtureRequest,
):
	record_type = RecordTypes.DNS_RECORD_TYPE_A.value
	record_fixture_name = get_record_fixture_name(record_type)
	record_fixture: dict = request.getfixturevalue(record_fixture_name)
	record_fixture["type"] = record_type
	record_main_field = record_type_main_field(record_type)
	old_record_data = record_fixture.copy()
	record_data = record_fixture.copy()
	old_record_data["name"] = "subdomain1"
	record_data["name"] = "subdomain2"
	old_record_data[record_main_field] = "old_value"
	record_data[record_main_field] = "new_value"

	mocker.patch.object(
		f_record_mixin, "increment_soa_serial", side_effect=Exception
	)
	m_ldap_record_instance = mocker.MagicMock()
	m_old_ldap_record_instance = mocker.MagicMock()
	m_soa_object = mocker.MagicMock()
	m_ldap_record_instance.create.return_value = {"result": 0}
	m_ldap_record_instance.soa_object = m_soa_object
	m_ldap_record_instance.as_dict = record_data
	m_ldap_record_instance.__fullname__ = mocker.Mock(
		return_value="mock_fullname"
	)
	mocker.patch(
		f"core.views.mixins.ldap.record.LDAPRecord",
		side_effect=[m_ldap_record_instance, m_old_ldap_record_instance],
	)

	with pytest.raises(exc_dns.DNSCouldNotIncrementSOA):
		f_record_mixin.update_record(
			record_data=record_data, old_record_data=old_record_data
		)


def test_update_record_different_name_raises_ldap_backend_error(
	mocker: MockerFixture,
	f_record_mixin: DNSRecordMixin,
	request: pytest.FixtureRequest,
):
	record_type = RecordTypes.DNS_RECORD_TYPE_A.value
	record_fixture_name = get_record_fixture_name(record_type)
	record_fixture: dict = request.getfixturevalue(record_fixture_name)
	record_fixture["type"] = record_type
	record_main_field = record_type_main_field(record_type)
	old_record_data = record_fixture.copy()
	record_data = record_fixture.copy()
	old_record_data["name"] = "subdomain1"
	record_data["name"] = "subdomain2"
	old_record_data[record_main_field] = "old_value"
	record_data[record_main_field] = "new_value"

	m_ldap_record_instance = mocker.MagicMock()
	m_old_ldap_record_instance = mocker.MagicMock()
	m_soa_object = mocker.MagicMock()
	m_ldap_record_instance.create.return_value = {"result": 1}
	m_ldap_record_instance.soa_object = m_soa_object
	m_ldap_record_instance.as_dict = record_data
	m_ldap_record_instance.__fullname__ = mocker.Mock(
		return_value="mock_fullname"
	)
	mocker.patch(
		f"core.views.mixins.ldap.record.LDAPRecord",
		side_effect=[m_ldap_record_instance, m_old_ldap_record_instance],
	)

	with pytest.raises(exc_base.LDAPBackendException):
		f_record_mixin.update_record(
			record_data=record_data, old_record_data=old_record_data
		)


def test_update_record_raises_type_mismatch(f_record_mixin: DNSRecordMixin):
	with pytest.raises(exc_dns.DNSRecordTypeMismatch):
		f_record_mixin.update_record(
			record_data={"type": RecordTypes.DNS_RECORD_TYPE_A.value},
			old_record_data={"type": RecordTypes.DNS_RECORD_TYPE_AAAA.value},
		)


def test_update_record_raises_zone_mismatch(f_record_mixin: DNSRecordMixin):
	with pytest.raises(exc_dns.DNSRecordZoneMismatch):
		f_record_mixin.update_record(
			record_data={
				"type": RecordTypes.DNS_RECORD_TYPE_A.value,
				"zone": "zone_a",
			},
			old_record_data={
				"type": RecordTypes.DNS_RECORD_TYPE_A.value,
				"zone": "zone_b",
			},
		)


@pytest.mark.parametrize(
	"record_type",
	(
		RecordTypes.DNS_RECORD_TYPE_A.value,
		RecordTypes.DNS_RECORD_TYPE_AAAA.value,
		RecordTypes.DNS_RECORD_TYPE_NS.value,
		RecordTypes.DNS_RECORD_TYPE_CNAME.value,
		RecordTypes.DNS_RECORD_TYPE_DNAME.value,
		RecordTypes.DNS_RECORD_TYPE_PTR.value,
		RecordTypes.DNS_RECORD_TYPE_TXT.value,
		RecordTypes.DNS_RECORD_TYPE_X25.value,
		RecordTypes.DNS_RECORD_TYPE_ISDN.value,
		RecordTypes.DNS_RECORD_TYPE_LOC.value,
		RecordTypes.DNS_RECORD_TYPE_HINFO.value,
		RecordTypes.DNS_RECORD_TYPE_SOA.value,
		RecordTypes.DNS_RECORD_TYPE_MX.value,
		RecordTypes.DNS_RECORD_TYPE_SRV.value,
	),
	ids=lambda t: RecordTypes(t).name,
)
def test_delete_record(
	mocker: MockerFixture,
	record_type: int,
	f_record_mixin: DNSRecordMixin,
	request: pytest.FixtureRequest,
	f_log_mixin: LogMixin,
):
	record_fixture_name = get_record_fixture_name(record_type)
	record_fixture: dict = request.getfixturevalue(record_fixture_name)
	record_fixture["type"] = record_type
	record_main_value = record_fixture[
		record_type_main_field(record_fixture["type"])
	]
	m_request = mocker.MagicMock()
	m_request.user.id = 1
	f_record_mixin.request = m_request
	m_delete = mocker.MagicMock()
	m_ldap_record_instance = mocker.MagicMock()
	m_ldap_record_instance.delete = m_delete
	m_ldap_record_instance.__fullname__ = mocker.Mock(
		return_value="mock_fullname"
	)
	m_ldap_record = mocker.patch(
		f"core.views.mixins.ldap.record.LDAPRecord",
		return_value=m_ldap_record_instance,
	)

	f_record_mixin.delete_record(record_data=record_fixture)
	m_ldap_record.assert_called_once_with(
		connection=f_record_mixin.ldap_connection,
		record_name=record_fixture["name"],
		record_zone=record_fixture["zone"],
		record_type=record_type,
		record_main_value=record_main_value,
	)
	m_delete.assert_called_once()

	f_log_mixin.log.assert_any_call(
		user=1,
		operation_type=LOG_ACTION_DELETE,
		log_target_class=LOG_CLASS_DNSR,
		log_target="mock_fullname",
	)


def test_delete_raises_no_connection(f_record_mixin: DNSRecordMixin):
	f_record_mixin.ldap_connection = None
	with pytest.raises(exc_ldap.LDAPConnectionNotOpen):
		f_record_mixin.delete_record(record_data={})
