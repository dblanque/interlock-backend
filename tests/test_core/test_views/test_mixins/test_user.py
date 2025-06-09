########################### Standard Pytest Imports ############################
import pytest
from pytest import FixtureRequest
from pytest_mock import MockerFixture, MockType
################################################################################
from core.views.mixins.user import UserMixin
from core.models.user import User, USER_TYPE_LDAP
from core.exceptions.base import BadRequest
from core.exceptions.users import UserDoesNotExist, UserNotLocalType
from tests.test_core.test_views.conftest import UserFactory

@pytest.fixture
def f_mixin():
	return UserMixin()

class TestValidatedUserPkList():
	def test_success(self, f_mixin: UserMixin):
		m_users_pk_lst = [1,2,3,4,5]
		m_initial_data = {"users": m_users_pk_lst}
		assert f_mixin.validated_user_pk_list(
			m_initial_data) == m_users_pk_lst

	def test_raises_on_bad_inner_value(self, f_mixin: UserMixin):
		m_initial_data = {"users": ["somevalue", 2, 3, 4,]}
		with pytest.raises(BadRequest):
			f_mixin.validated_user_pk_list(m_initial_data)

	@pytest.mark.parametrize(
		"value",
		(
			[],
			{"some": "dict"},
			False,
		),
	)
	def test_raises_on_bad_value(self, f_mixin: UserMixin, value):
		m_initial_data = {"users": value}
		with pytest.raises(BadRequest):
			f_mixin.validated_user_pk_list(m_initial_data)

@pytest.mark.django_db
class TestUserChangeStatus():
	@pytest.mark.parametrize(
		"previous_status, target_status, expected_status",
		(
			(True, True, True),
			(False, False, False),
			(False, True, True),
			(True, False, False),
		),
	)
	def test_success(
		self,
		f_mixin: UserMixin,
		user_factory: UserFactory,
		previous_status: bool,
		target_status: bool,
		expected_status: bool,
	):
		# Mock User
		m_user: User = user_factory(
			username="teststatuschange", email=None)
		m_user.is_enabled = previous_status
		m_user.save()

		f_mixin.user_change_status(m_user.id, target_status=target_status)

		m_user.refresh_from_db()
		assert m_user.is_enabled == expected_status

	def test_raises_not_exists(self, f_mixin: UserMixin):
		with pytest.raises(UserDoesNotExist):
			f_mixin.user_change_status(
				user_pk=999,
				target_status=True,
				raise_exception=True,
			)

	def test_returns_none_on_not_exists(self, f_mixin: UserMixin):
		assert f_mixin.user_change_status(
			user_pk=999,
			target_status=True,
			raise_exception=False,
		) is None

	def test_raises_not_local_user(
		self,
		f_mixin: UserMixin,
		user_factory: UserFactory,
	):
		m_user = user_factory(
			username="testraisesnotlocal",
			email=None,
			user_type=USER_TYPE_LDAP,
		)
		m_user.save()
		with pytest.raises(UserNotLocalType):
			f_mixin.user_change_status(m_user.pk, target_status=True)