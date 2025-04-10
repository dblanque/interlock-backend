import pytest
from core.views.mixins.ldap.record import DNSRecordMixin
from core.exceptions import dns as exc_dns
from core.models.dns import LDAPRecord
from core.models.structs.ldap_dns_record import DNS_RECORD
from core.ldap.defaults import LDAP_DOMAIN

@pytest.fixture
def f_record_mixin(mocker):
    mixin = DNSRecordMixin()
    mocker.patch.object(mixin, 'ldap_connection', mocker.MagicMock())
    return mixin

@pytest.fixture
def f_mock_record(mocker):
    mock = mocker.MagicMock(spec=LDAPRecord)
    mock.structure = mocker.MagicMock(spec=DNS_RECORD)
    mock.structure.getData.return_value = {"test": "data"}
    return mock

class TestDNSRecordMixin:
    def test_validate_record_data_missing_type(self, f_record_mixin):
        with pytest.raises(exc_dns.DNSRecordTypeMissing):
            f_record_mixin.validate_record_data({})

    def test_validate_record_data_root_zone(self, f_record_mixin):
        with pytest.raises(exc_dns.DNSRootServersOnlyCLI):
            f_record_mixin.validate_record_data({
                "type": "A",
                "zone": "Root DNS Servers"
            })

    def test_create_record_success(self, f_record_mixin, f_mock_record, mocker):
        mocker.patch('core.views.mixins.ldap.record.LDAPRecord', return_value=f_mock_record)
        mocker.patch.object(f_record_mixin, 'increment_soa_serial')

        record_data = {
            "name": "test",
            "type": "A",
            "zone": LDAP_DOMAIN,
            "address": "192.168.1.1"
        }
        
        result = f_record_mixin.create_record(record_data)
        assert result is not None
        f_mock_record.create.assert_called_once()

    def test_update_record_name_change(self, f_record_mixin, f_mock_record, mocker):
        mocker.patch('core.views.mixins.ldap.record.LDAPRecord', return_value=f_mock_record)
        mocker.patch.object(f_record_mixin, 'increment_soa_serial')
        
        old_data = {
            "name": "old",
            "type": "A",
            "zone": LDAP_DOMAIN,
            "address": "192.168.1.1"
        }
        new_data = {
            "name": "new",
            "type": "A",
            "zone": LDAP_DOMAIN,
            "address": "192.168.1.1"
        }
        
        result = f_record_mixin.update_record(new_data, old_data)
        assert result is not None
        f_mock_record.create.assert_called_once()
        f_mock_record.delete.assert_called_once()
