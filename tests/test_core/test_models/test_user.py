import pytest
from django.core.exceptions import ValidationError
from django.db.transaction import TransactionManagementError
from django.db.utils import IntegrityError
from core.models.user import User, USER_TYPE_LOCAL, USER_TYPE_LDAP
from django.db import transaction


@pytest.mark.django_db
class TestUserModel:
	@pytest.fixture(autouse=True)
	def setup_password(self):
		"""Fixture to provide a default password for all test users"""
		self.default_password = "somepassword"

	def test_create_user_minimal(self):
		"""Test creating a user with minimal required fields"""
		user = User.objects.create(
			username="test_create_user_minimal", user_type=USER_TYPE_LOCAL, is_enabled=True
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
			is_enabled=False,
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

	def test_distinguished_name_ldap(self):
		"""Test distinguished_name for LDAP user"""
		user = User.objects.create(
			username="test_distinguished_name_ldap",
			password=self.default_password,
			user_type=USER_TYPE_LDAP,
			dn="cn=test,ou=users,dc=example,dc=com",
		)
		assert user.distinguished_name == "cn=test,ou=users,dc=example,dc=com"

	def test_distinguished_name_non_ldap(self):
		"""Test distinguished_name for non-LDAP user"""
		user = User.objects.create(
			username="test_distinguished_name_non_ldap",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL,
		)
		assert user.distinguished_name is None

	def test_encryptedPassword_property(self, mocker):
		"""Test the encryptedPassword property"""
		# Setup mock values for the password fields
		mock_fields = {
			"ldap_password_aes": b"aes_data",
			"ldap_password_ct": b"ct_data",
			"ldap_password_nonce": b"nonce_data",
			"ldap_password_tag": b"tag_data",
		}

		# Create a mock user with the fields
		user = User(**mock_fields)

		# Test the property
		result = user.encryptedPassword
		assert result == (b"aes_data", b"ct_data", b"nonce_data", b"tag_data")

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
			ldap_password_tag=None,
		)

		# Test with all fields not None (should pass)
		User.objects.create(
			username="test_password_constraint_all_or_none_02",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL,
			ldap_password_aes=b"aes",
			ldap_password_ct=b"ct",
			ldap_password_nonce=b"nonce",
			ldap_password_tag=b"tag",
		)

		# Test with some fields None (should fail)
		with pytest.raises(IntegrityError):
			User.objects.create(
				username="test_password_constraint_all_or_none_03",
				password=self.default_password,
				user_type=USER_TYPE_LOCAL,
				ldap_password_aes=b"aes",
				ldap_password_ct=None,
				ldap_password_nonce=b"nonce",
				ldap_password_tag=b"tag",
			)

	def test_user_type_required(self):
		"""Test that user_type is required"""
		with pytest.raises(IntegrityError):
			User.objects.create(username="test_user_type_required", user_type=None, is_enabled=True)

	def test_is_enabled_default(self):
		"""Test that is_enabled defaults to True"""
		user = User.objects.create(username="test_is_enabled_default", user_type=USER_TYPE_LOCAL)
		assert user.is_enabled is True

	def test_recovery_codes_field(self):
		"""Test the recovery_codes ArrayField"""
		user = User.objects.create(
			username="test_recovery_codes_field",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL,
			recovery_codes=["code1", "code2", "code3"],
		)
		assert user.recovery_codes == ["code1", "code2", "code3"]

	@pytest.mark.parametrize(
		"field_name,max_length",
		[
			("first_name", 255),
			("last_name", 255),
			("dn", 128),
		],
	)
	def test_max_length_constraints(self, field_name, max_length):
		"""Test max length constraints on CharFields"""
		# Create a string that's too long
		long_string = "x" * (max_length + 1)

		# Create a valid user first
		user = User.objects.create(
			username="test_max_length_constraints",
			password=self.default_password,
			user_type=USER_TYPE_LOCAL,
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
			user_type=USER_TYPE_LOCAL,
		)
		assert str(user) == f"test_str_representation"

	# BaseUserManager tests through User implementation
	def test_create_user_via_manager(self):
		"""Test BaseUserManager.create_user through User model"""
		user = User.objects.create_user(
			username="manager_create_user", password=self.default_password
		)
		assert user.pk is not None
		assert user.check_password(self.default_password)
		assert user.is_staff is False
		assert user.is_superuser is False

	def test_create_superuser_via_manager(self):
		"""Test BaseUserManager.create_superuser through User model"""
		user = User.objects.create_superuser(
			username="manager_create_superuser", password=self.default_password
		)
		assert user.is_staff is True
		assert user.is_superuser is True

	def test_create_superuser_validation(self):
		"""Test BaseUserManager.create_superuser validation"""
		with pytest.raises(ValueError, match="Superuser must have is_staff=True"):
			User.objects.create_superuser(
				username="invalid_superuser1", password=self.default_password, is_staff=False
			)

		with pytest.raises(ValueError, match="Superuser must have is_superuser=True"):
			User.objects.create_superuser(
				username="invalid_superuser2", password=self.default_password, is_superuser=False
			)

	def test_get_queryset_excludes_deleted(self):
		"""Test BaseUserManager.get_queryset excludes deleted users"""
		active_user = User.objects.create_user(
			username="active_user", password=self.default_password
		)
		deleted_user = User.objects.create_user(
			username="deleted_user", password=self.default_password, deleted=True
		)

		queryset = User.objects.get_queryset()
		assert active_user in queryset
		assert deleted_user not in queryset

	def test_get_full_queryset_includes_deleted(self):
		"""Test BaseUserManager.get_full_queryset includes deleted users"""
		active_user = User.objects.create_user(
			username="active_user2", password=self.default_password
		)
		deleted_user = User.objects.create_user(
			username="deleted_user2", password=self.default_password, deleted=True
		)

		queryset = User.objects.get_full_queryset()
		assert active_user in queryset
		assert deleted_user in queryset

	# BaseUser tests through User implementation
	def test_user_properties(self):
		"""Test BaseUser properties through User model"""
		user = User.objects.create_user(
			username="test_properties", password=self.default_password, email="props@example.com"
		)

		assert user.get_username() == "test_properties"
		assert user.get_email() == "props@example.com"
		assert user.get_uid() == user.id
		assert user.date_joined == user.created_at
		assert user.is_anonymous is False
		assert user.is_authenticated is True
		assert user.is_active is True

	def test_password_management(self):
		"""Test BaseUser password methods through User model"""
		user = User.objects.create_user(
			username="test_password_management", password=self.default_password
		)

		# Test password change
		user.set_password("new_password123")
		assert user.check_password("new_password123") is True
		assert user.check_password(self.default_password) is False

		# Test unusable password
		user.set_unusable_password()
		assert user.has_usable_password() is False

	def test_session_auth_hash(self):
		"""Test BaseUser session auth hash through User model"""
		user = User.objects.create_user(
			username="test_session_auth_hash", password=self.default_password
		)

		original_hash = user.get_session_auth_hash()
		assert isinstance(original_hash, str)

		# Hash should change when password changes
		user.set_password("new_password123")
		new_hash = user.get_session_auth_hash()
		assert original_hash != new_hash

	def test_username_uniqueness(self):
		"""Test BaseUser username uniqueness through User model"""
		User.objects.create_user(username="unique_user", password=self.default_password)

		with pytest.raises(IntegrityError):
			User.objects.create_user(
				username="unique_user",  # Duplicate
				password=self.default_password,
			)

	def test_email_uniqueness(self):
		"""Test email uniqueness with null=True scenario"""
		# Test non-null email uniqueness
		email = "unique@example.com"

		with transaction.atomic():
			# Create first user with email
			User.objects.create_user(username="user1", password=self.default_password, email=email)

		# Attempt to create second user with same email - should fail
		with pytest.raises((IntegrityError, TransactionManagementError)):
			with transaction.atomic():
				User.objects.create_user(
					username="user2",
					password=self.default_password,
					email=email,  # Duplicate non-null email
				)

		with transaction.atomic():
			# Test multiple NULL emails are allowed
			User.objects.create_user(
				username="user3",
				password=self.default_password,
				email=None,  # First NULL
			)
			User.objects.create_user(
				username="user4",
				password=self.default_password,
				email=None,  # Second NULL - should be allowed
			)

		# Verify count of NULL emails
		assert User.objects.filter(email__isnull=True).count() == 2

	def test_required_fields(self):
		"""Test BaseUser required fields through User model"""
		# Username is required
		with pytest.raises(ValueError, match="must have a username"):
			User.objects.create_user(username=None, password=self.default_password)

		# Password is required (validation error, not integrity error)
		with pytest.raises(ValidationError):
			user = User(username="no_password")
			user.full_clean()
