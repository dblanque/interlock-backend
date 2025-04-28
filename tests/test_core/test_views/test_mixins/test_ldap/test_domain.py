import pytest
from core.views.mixins.ldap.domain import DomainViewMixin
from core.models.dns import LDAPRecord, DATE_FMT
from core.ldap.defaults import LDAP_DOMAIN
from unittest.mock import MagicMock
from datetime import datetime


@pytest.fixture
def f_domain_mixin():
	mixin = DomainViewMixin()
	mixin.connection = MagicMock()
	return mixin


@pytest.fixture
def f_mock_soa_record():
	mock = MagicMock(spec=LDAPRecord)
	mock.data = {"dwSerialNo": 100, "serial": 100}
	return mock


class TestDomainViewMixinUtils:
	def test_get_zone_soa(self, f_domain_mixin: DomainViewMixin, f_mock_soa_record: LDAPRecord, mocker):
		mocker.patch(
			"core.views.mixins.ldap.domain.LDAPRecord",
			return_value=f_mock_soa_record,
		)

		result = f_domain_mixin.get_zone_soa(LDAP_DOMAIN)
		assert result == f_mock_soa_record.data

	def test_increment_soa_serial(self, f_domain_mixin: DomainViewMixin, f_mock_soa_record: LDAPRecord):
		result = f_domain_mixin.increment_soa_serial(f_mock_soa_record, 101)
		f_mock_soa_record.update.assert_called_once()

	@staticmethod
	@pytest.mark.parametrize(
		"as_epoch, expected",
		(
			(True, int(datetime.today().strftime(DATE_FMT) + "01")),
			(False, 1),
		),
	)
	def test_create_initial_serial(as_epoch: bool, expected: int, f_domain_mixin: DomainViewMixin):
		assert f_domain_mixin.create_initial_serial(
			as_epoch_serial=as_epoch
		) == expected
