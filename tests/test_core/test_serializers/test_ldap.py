########################### Standard Pytest Imports ############################
import pytest

################################################################################
from core.ldap.adsi import LDAP_PERMS
from core.ldap.countries import LDAP_COUNTRIES
from rest_framework.exceptions import ValidationError

from core.serializers.ldap import (
	ldap_user_validator_se,
	dn_validator_se,
	country_validator,
	country_dcc_validator,
	country_iso_validator,
	ldap_permission_validator,
	website_validator,
)


class TestLdapUserValidator:
	@pytest.mark.parametrize(
		"username",
		(
			"johndoe",
			"john_doe",
			"john-doe",
			"johndoe123",
			"JDoe",
			"j",
			"JOHN_DOE_123",
		),
	)
	def test_success(self, username: str):
		assert ldap_user_validator_se(username)

	@pytest.mark.parametrize(
		"username",
		(
			"john.doe",
			"john@doe",
			"john[doe]",
			'john"doe',
			"john:doe",
			"john;doe",
			"john|doe",
			"john=doe",
			"john+doe",
			"john*doe",
			"john?doe",
			"john<doe",
			"john>doe",
			"john/doe",
			"john\\doe",
			"john,doe",
			"john doe",
		),
	)
	def test_raises(self, username: str):
		with pytest.raises(ValidationError):
			ldap_user_validator_se(username)


class TestLdapPermissionValidator:
	@pytest.mark.parametrize("value", [_k for _k in LDAP_PERMS.keys()])
	def test_success(
		self,
		value: str,
	):
		assert ldap_permission_validator(value) == value

	def test_raises(self):
		with pytest.raises(ValidationError):
			ldap_permission_validator("NON_EXISTING_PERMISSION")


class TestLdapCountryValidator:
	@pytest.mark.parametrize(
		"country",
		[country for country in LDAP_COUNTRIES.keys()],
	)
	def test_success(
		self,
		country: str,
	):
		assert country_validator(country) == country

	def test_raises(self):
		with pytest.raises(ValidationError):
			country_validator("Non Existing Country")


class TestLdapCountryDCCValidator:
	@pytest.mark.parametrize(
		"country",
		[country for country in LDAP_COUNTRIES.keys()],
		ids=lambda x: f"{x} ({LDAP_COUNTRIES[x]['dccCode']})",
	)
	def test_success(
		self,
		country: str,
	):
		dcc_code = int(LDAP_COUNTRIES[country]["dccCode"])
		assert country_dcc_validator(dcc_code) == dcc_code

	def test_zero_returns(self):
		assert country_dcc_validator(0)

	@pytest.mark.parametrize(
		"value",
		(
			None,
			False,
			999,
		),
	)
	def test_raises(self, value):
		with pytest.raises(ValidationError):
			country_dcc_validator(value)


class TestLdapCountryISOValidator:
	@pytest.mark.parametrize(
		"country",
		[country for country in LDAP_COUNTRIES.keys()],
		ids=lambda x: f"{x} ({LDAP_COUNTRIES[x]['isoCode']})",
	)
	def test_success(
		self,
		country: str,
	):
		iso_code = LDAP_COUNTRIES[country]["isoCode"]
		assert country_iso_validator(iso_code) == iso_code

	def test_raises_on_length(self):
		with pytest.raises(ValidationError):
			country_iso_validator("BADCODE")

	def test_raises_on_bad_code(self):
		with pytest.raises(ValidationError):
			country_iso_validator("ZZ")


class TestDistinguishedNameValidator:
	def test_success(self):
		assert dn_validator_se("CN=User,DC=example,DC=com")

	@pytest.mark.parametrize(
		"value",
		(
			"CN=BadCN=Bad,@@FGPL=",
			"SomeValue",
		),
	)
	def test_raise(self, value: str):
		with pytest.raises(ValidationError):
			dn_validator_se(value)


class TestWebsiteValidator:
	@pytest.mark.parametrize(
		"value",
		(
			"example.com",
			"sub.example.com",
			"sub-with-hyphen.example.com",
			"sub.multi.example.com",
			"example.com.ar",
		),
	)
	def test_success(self, value: str):
		assert website_validator(value)
		assert website_validator(f"http://{value}")
		assert website_validator(f"https://{value}")
		assert website_validator(f"http://{value}/")
		assert website_validator(f"https://{value}/")

	@pytest.mark.parametrize(
		"value",
		(
			"somebadvalue",
			"an@email.com",
		),
	)
	def test_raises(self, value: str):
		with pytest.raises(ValidationError):
			website_validator(value)
