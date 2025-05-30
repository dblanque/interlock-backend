import pytest
from django.db import transaction
from core.models.user import User
from core.models.application import Application, ApplicationSecurityGroup
from core.exceptions.application_group import (
	ApplicationGroupExists,
	ApplicationGroupDoesNotExist,
)
from core.views.mixins.application_group import (
	ApplicationSecurityGroupViewMixin,
)
from core.exceptions.base import BadRequest

################################################################################
# Fixtures
################################################################################


@pytest.fixture
def mixin() -> ApplicationSecurityGroupViewMixin:
	"""Fixture providing an instance of the mixin class"""
	return ApplicationSecurityGroupViewMixin()


@pytest.fixture
def test_application(db):
	"""Fixture creating a test application in the database"""
	return Application.objects.create(
		name="Test Application",
		enabled=True,
		client_id="test-client-id",
		client_secret="test-client-secret",
		redirect_uris="http://localhost:8000/callback",
		scopes="openid profile",
	)


@pytest.fixture
def test_user(db):
	"""Fixture creating a test user in the database"""
	return User.objects.create(
		username="testuser",
		email="test@example.com",
		first_name="Test",
		last_name="User",
	)


@pytest.fixture
def test_application_group(db, test_application: Application, test_user):
	"""Fixture creating a test application group in the database"""
	group = ApplicationSecurityGroup.objects.create(
		application=test_application,
		ldap_objects=["CN=TestGroup,OU=Groups,DC=test,DC=com"],
		enabled=True,
	)
	group.users.add(test_user)
	return group


@pytest.fixture
def application_group_data(test_application: Application, test_user):
	"""Fixture providing sample application group data"""
	return {
		"application": test_application.id,
		"users": [test_user.id],
		"ldap_objects": ["CN=TestGroup,OU=Groups,DC=test,DC=com"],
		"enabled": True,
	}


################################################################################
# Tests
################################################################################


@pytest.mark.django_db
class TestApplicationSecurityGroupViewMixin:
	def test_insert_application_group_success(
		self,
		mixin: ApplicationSecurityGroupViewMixin,
		test_application: Application,
		test_user,
		application_group_data,
	):
		# Verify no groups exist initially
		assert ApplicationSecurityGroup.objects.count() == 0

		# Test the method
		with transaction.atomic():
			mixin.insert_application_group(application_group_data)

		# Verify the group was created
		assert ApplicationSecurityGroup.objects.count() == 1
		group = ApplicationSecurityGroup.objects.first()
		assert group.application == test_application
		assert list(group.users.all()) == [test_user]
		assert group.ldap_objects == application_group_data["ldap_objects"]
		assert group.enabled is True

	def test_insert_application_group_exists(
		self,
		mixin: ApplicationSecurityGroupViewMixin,
		test_application_group: ApplicationSecurityGroup,
		application_group_data,
	):
		# Verify group exists initially
		assert ApplicationSecurityGroup.objects.count() == 1

		# Test and verify the exception
		with pytest.raises(ApplicationGroupExists):
			mixin.insert_application_group(application_group_data)

		# Verify no additional groups were created
		assert ApplicationSecurityGroup.objects.count() == 1

	def test_insert_application_group_invalid_data(
		self,
		mixin: ApplicationSecurityGroupViewMixin,
		test_application: Application,
		application_group_data,
	):
		# Corrupt the data
		invalid_data = application_group_data.copy()
		invalid_data["users"] = [999]  # Non-existent user ID

		# Test and verify the exception
		with pytest.raises(BadRequest):
			mixin.insert_application_group(invalid_data)

		# Verify no groups were created
		assert ApplicationSecurityGroup.objects.count() == 0

	def test_list_application_groups(
		self, mixin: ApplicationSecurityGroupViewMixin, test_application_group
	):
		# Test the method
		result = mixin.list_application_groups()

		# Verify the result
		assert isinstance(result, dict)
		assert "application_groups" in result
		assert "headers" in result
		assert len(result["application_groups"]) == 1
		assert (
			result["application_groups"][0]["id"] == test_application_group.id
		)
		assert (
			result["application_groups"][0]["application"]
			== test_application_group.application.name
		)
		assert result["application_groups"][0]["enabled"] is True

	def test_retrieve_application_success(
		self,
		mixin: ApplicationSecurityGroupViewMixin,
		test_application_group: ApplicationSecurityGroup,
		test_user,
	):
		# Test the method
		result = mixin.retrieve_application(test_application_group.id)

		# Verify the result
		assert isinstance(result, dict)
		assert result["id"] == test_application_group.id
		assert (
			result["application"]["id"] == test_application_group.application.id
		)
		assert (
			result["application"]["name"]
			== test_application_group.application.name
		)
		assert result["enabled"] is True
		assert result["users"] == [test_user.id]
		assert result["ldap_objects"] == test_application_group.ldap_objects

	def test_retrieve_application_not_found(self, mixin):
		# Test and verify the exception
		with pytest.raises(ApplicationGroupDoesNotExist):
			mixin.retrieve_application(999)  # Non-existent ID

	@pytest.mark.parametrize(
		"use_users",
		(
			True,
			False,
		),
	)
	def test_update_application_group_success(
		self,
		use_users: bool,
		mixin: ApplicationSecurityGroupViewMixin,
		test_application_group: ApplicationSecurityGroup,
		test_user: User,
		test_application: Application,
	):
		# Create a second user for testing
		new_user = User.objects.create(
			username="newuser",
			email="new@example.com",
			first_name="New",
			last_name="User",
		)

		# Prepare update data
		update_data = {
			"ldap_objects": ["CN=NewGroup,OU=Groups,DC=test,DC=com"],
			"enabled": False,
			"application": test_application.id,
		}
		if use_users:
			update_data["users"] = [new_user.id]

		# Test the method
		with transaction.atomic():
			mixin.update_application_group(
				test_application_group.id, update_data
			)

		# Refresh from database
		test_application_group.refresh_from_db()

		# Verify the updates
		if use_users:
			assert list(test_application_group.users.all()) == [new_user]
		else:
			assert list(test_application_group.users.all()) == [test_user]
		assert (
			test_application_group.ldap_objects == update_data["ldap_objects"]
		)
		assert test_application_group.enabled is False

	def test_update_application_group_not_found(
		self, mixin: ApplicationSecurityGroupViewMixin, application_group_data
	):
		# Test and verify the exception
		with pytest.raises(ApplicationGroupDoesNotExist):
			mixin.update_application_group(
				999, application_group_data
			)  # Non-existent ID

	def test_update_application_group_app_id_does_not_match(
		self,
		mixin: ApplicationSecurityGroupViewMixin,
		application_group_data,
		test_application_group: ApplicationSecurityGroup,
	):
		application_group_data["application"] += 1
		# Test and verify the exception
		with pytest.raises(BadRequest) as e:
			mixin.update_application_group(
				test_application_group.id,
				application_group_data,
			)
		assert "does not match" in e.value.detail.get("detail")

	def test_update_application_group_invalid_data(
		self,
		mixin: ApplicationSecurityGroupViewMixin,
		test_application_group: ApplicationSecurityGroup,
		application_group_data,
	):
		# Corrupt the data
		invalid_data = application_group_data.copy()
		invalid_data["users"] = [999]  # Non-existent user ID
		invalid_data["enabled"] = "ABCD"

		# Test and verify the exception
		with pytest.raises(BadRequest):
			mixin.update_application_group(
				test_application_group.id, invalid_data
			)

		# Verify no changes were made
		original_users = list(test_application_group.users.all())
		test_application_group.refresh_from_db()
		assert list(test_application_group.users.all()) == original_users

	def test_change_application_group_status_success(
		self, mixin: ApplicationSecurityGroupViewMixin, test_application_group
	):
		# Verify initial state
		assert test_application_group.enabled is True

		# Test the method
		mixin.change_application_group_status(
			test_application_group.id, {"enabled": False}
		)

		# Refresh from database
		test_application_group.refresh_from_db()

		# Verify the change
		assert test_application_group.enabled is False

	def test_change_application_group_status_not_found(self, mixin):
		# Test and verify the exception
		with pytest.raises(ApplicationGroupDoesNotExist):
			mixin.change_application_group_status(
				999, {"enabled": False}
			)  # Non-existent ID

	def test_change_application_group_status_missing_field(
		self, mixin: ApplicationSecurityGroupViewMixin, test_application_group
	):
		# Test and verify the exception
		with pytest.raises(BadRequest):
			mixin.change_application_group_status(test_application_group.id, {})

	def test_change_application_group_status_invalid_type(
		self, mixin: ApplicationSecurityGroupViewMixin, test_application_group
	):
		# Test and verify the exception
		with pytest.raises(BadRequest):
			mixin.change_application_group_status(
				test_application_group.id, {"enabled": "not_a_boolean"}
			)

	def test_delete_application_group_success(
		self, mixin: ApplicationSecurityGroupViewMixin, test_application_group
	):
		# Verify group exists initially
		assert ApplicationSecurityGroup.objects.count() == 1

		# Test the method
		mixin.delete_application_group(test_application_group.id)

		# Verify the group was deleted
		assert ApplicationSecurityGroup.objects.count() == 0
		assert not ApplicationSecurityGroup.objects.filter(
			id=test_application_group.id
		).exists()

	def test_delete_application_group_not_found(self, mixin):
		# Test and verify the exception
		with pytest.raises(ApplicationGroupDoesNotExist):
			mixin.delete_application_group(999)  # Non-existent ID
