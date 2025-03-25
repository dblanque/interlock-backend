import pytest
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from core.models.user import User, USER_TYPE_LOCAL, USER_TYPE_LDAP

@pytest.mark.django_db
class TestUserModel:
	@pytest.fixture(autouse=True)
	def setup_password(self):
		"""Fixture to provide a default password for all test users"""
		self.default_password = "somepassword"

	def test_create_user_minimal(self):
		"""Test creating a user with minimal required fields"""
		user = User.objects.create(
			username="test_create_user_minimal",
			user_type=USER_TYPE_LOCAL,
			is_enabled=True
		)
		assert user.pk is not None
		assert user.user_type == USER_TYPE_LOCAL
		assert user.is_enabled is True
		assert user.is_user_local() is True

	def test_create_user_full(self):
		"""Test creating a user with all fields"""
		user = User.objects.create(
			username="test_create_user_full",
			password=self.default_password,
			first_name="John",
			last_name="Doe",
			email="john.doe@example.com",
			dn="cn=john,ou=users,dc=example,dc=com",
			user_type=USER_TYPE_LDAP,
			recovery_codes=["123456", "654321"],
			is_enabled=False
		)
		assert user.pk is not None
		assert user.first_name == "John"
		assert user.last_name == "Doe"
		assert user.email == "john.doe@example.com"
		assert user.dn == "cn=john,ou=users,dc=example,dc=com"
		assert user.user_type == USER_TYPE_LDAP
		assert user.recovery_codes == ["123456", "654321"]
		assert user.is_enabled is False
		assert user.is_user_local() is False

	def test_get_distinguishedname_ldap(self):
		"""Test get_distinguishedname for LDAP user"""
		user = User.objects.create(
			username="test_get_distinguishedname_ldap",
			password=self.default_password,
			user_type=USER_TYPE_LDAP,
			dn="cn=test,ou=users,dc=example,dc=com"
		)
		assert user.get_distinguishedname() == "cn=test,ou=users,dc=example,dc=com"

	def test_get_distinguishedname_non_ldap(self):
		"""Test get_distinguishedname for non-LDAP user"""
		user = User.objects.create(
			username="test_get_distinguishedname_non_ldap",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL,
		)
		assert user.get_distinguishedname() is False

	def test_encryptedPassword_property(self, mocker):
		"""Test the encryptedPassword property"""
		# Setup mock values for the password fields
		mock_fields = {
			
			'ldap_password_aes': b'aes_data',
			'ldap_password_ct': b'ct_data',
			'ldap_password_nonce': b'nonce_data',
			'ldap_password_tag': b'tag_data'
		}
		
		# Create a mock user with the fields
		user = User(**mock_fields)

		# Test the property
		result = user.encryptedPassword
		assert result == (b'aes_data', b'ct_data', b'nonce_data', b'tag_data')

	def test_password_constraint_all_or_none(self):
		"""Test the password fields constraint (all or none)"""
		# Test with all fields None (should pass)
		User.objects.create(
			username="test_password_constraint_all_or_none_01",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL,
			ldap_password_aes=None,
			ldap_password_ct=None,
			ldap_password_nonce=None,
			ldap_password_tag=None
		)

		# Test with all fields not None (should pass)
		User.objects.create(
			username="test_password_constraint_all_or_none_02",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL,
			ldap_password_aes=b'aes',
			ldap_password_ct=b'ct',
			ldap_password_nonce=b'nonce',
			ldap_password_tag=b'tag'
		)

		# Test with some fields None (should fail)
		with pytest.raises(IntegrityError):
			User.objects.create(
				username="test_password_constraint_all_or_none_03",
				password=self.default_password,
				user_type=USER_TYPE_LOCAL,
				ldap_password_aes=b'aes',
				ldap_password_ct=None,
				ldap_password_nonce=b'nonce',
				ldap_password_tag=b'tag'
			)

	def test_user_type_required(self):
		"""Test that user_type is required"""
		with pytest.raises(IntegrityError):
			User.objects.create(
				username="test_user_type_required",
				user_type=None,
				is_enabled=True
			)

	def test_is_enabled_default(self):
		"""Test that is_enabled defaults to True"""
		user = User.objects.create(
			username="test_is_enabled_default",
			user_type=USER_TYPE_LOCAL
		)
		assert user.is_enabled is True

	def test_recovery_codes_field(self):
		"""Test the recovery_codes ArrayField"""
		user = User.objects.create(
			username="test_recovery_codes_field",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL,
			recovery_codes=["code1", "code2", "code3"]
		)
		assert user.recovery_codes == ["code1", "code2", "code3"]

	@pytest.mark.parametrize("field_name,max_length", [
		("first_name", 255),
		("last_name", 255),
		("dn", 128),
	])
	def test_max_length_constraints(self, field_name, max_length):
		"""Test max length constraints on CharFields"""
		# Create a string that's too long
		long_string = "x" * (max_length + 1)
		
		# Create a valid user first
		user = User.objects.create(
			username="test_max_length_constraints",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL
		)
		
		# Try to set the long string on the field
		setattr(user, field_name, long_string)
		
		with pytest.raises(ValidationError):
			user.full_clean()

	def test_email_validation(self):
		"""Test email field validation"""
		user = User.objects.create(
			username="test_email_validation",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL,
		)

		# Test invalid email
		user.email = "not-an-email"
		with pytest.raises(ValidationError):
			user.full_clean()
		
		# Test valid email
		user.email = "valid@example.com"
		user.full_clean()  # Should not raise

	def test_str_representation(self):
		"""Test the string representation of the user"""
		# Test with no names
		user = User.objects.create(
			username="test_str_representation",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL
		)
		assert str(user) == f"test_str_representation"
