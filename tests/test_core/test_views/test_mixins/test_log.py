import pytest
from pytest_mock import MockType, MockerFixture
from django.db import transaction
from core.models.user import User
from core.models.log import Log
from core.views.mixins.logs import LogMixin
from core.models.choices.log import (
	LOG_ACTION_CREATE,
	LOG_ACTION_READ,
	LOG_ACTION_UPDATE,
	LOG_ACTION_DELETE,
	LOG_CLASS_USER,
	LOG_EXTRA_USER_END_USER_UPDATE,
)
from core.models.types.settings import TYPE_INTEGER
from core.constants.attrs.local import LOCAL_ATTR_TYPE, LOCAL_ATTR_VALUE
from core.models.interlock_settings import (
	InterlockSetting,
	INTERLOCK_SETTINGS_LOG_MAX,
)

@pytest.fixture
def log_mixin():
	return LogMixin()


@pytest.fixture
def test_user():
	return User.objects.create_user(
		username="testuser", password="testpass", email="test@example.com"
	)

@pytest.fixture(autouse=True)
def f_create_default_settings():
	from core.setup.interlock_setting import create_default_interlock_settings
	create_default_interlock_settings()

@pytest.fixture(autouse=True)
def f_patch_log_max():
	m_log_max = InterlockSetting.objects.update_or_create(
		defaults={
			LOCAL_ATTR_TYPE: TYPE_INTEGER,
			LOCAL_ATTR_VALUE: 5,
		},
		name=INTERLOCK_SETTINGS_LOG_MAX,
	)
	# Corroborate effective change.
	assert InterlockSetting.objects.get(
		name=INTERLOCK_SETTINGS_LOG_MAX
	).value == 5
	return m_log_max

@pytest.mark.django_db
class TestLogMixin:
	def test_log_with_invalid_operation_type(
		self,
		mocker: MockerFixture,
		log_mixin: LogMixin,
		test_user,
	):
		# Setup
		m_logger = mocker.patch("core.views.mixins.logs.logger")

		# Execute
		result = log_mixin.log(
			user=test_user,
			operation_type="TEST_OPERATION",
			log_target_class="TestClass",
		)

		# Verify
		assert result is None
		m_logger.warning.assert_called_once_with(
			"%s log option does not exist in InterlockSettings Model.",
			"ILCK_LOG_TEST_OPERATION"
		)

	def test_log_with_invalid_user_type(self, log_mixin: LogMixin):
		# Execute & Verify
		with pytest.raises(TypeError, match="user must be of type int | User"):
			log_mixin.log(
				user="invalid_user",
				operation_type=LOG_ACTION_READ,
				log_target_class=LOG_CLASS_USER,
			)

	def test_log_with_user_object(
		self,
		mocker: MockerFixture,
		log_mixin: LogMixin,
		test_user,
	):
		# Setup
		mocker.patch.object(
			Log.objects,
			"aggregate",
			return_value={"total_logs": 0, "max_id": 0},
		)
		mocker.patch.object(Log.objects, "order_by")
		mocker.patch.object(Log.objects, "filter")

		# Execute
		m_save: MockType = mocker.patch.object(Log, "save")
		log_mixin.log(
			user=test_user,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			message=LOG_EXTRA_USER_END_USER_UPDATE,
		)

		# Verify
		m_save.assert_called_once()

	def test_log_with_user_id(
		self,
		mocker: MockerFixture,
		log_mixin: LogMixin,
		test_user,
	):
		# Setup
		mocker.patch.object(
			Log.objects,
			"aggregate",
			return_value={"total_logs": 0, "max_id": 0},
		)
		mocker.patch.object(Log.objects, "order_by")
		mocker.patch.object(Log.objects, "filter")

		# Execute
		m_save: MockType = mocker.patch.object(Log, "save")
		log_mixin.log(
			user=test_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
		)

		# Verify
		assert m_save.called

	def test_log_rotation_needed(
		self,
		mocker: MockerFixture,
		log_mixin: LogMixin,
		test_user,
	):
		# Setup
		mocker.patch.object(
			Log.objects,
			"aggregate",
			return_value={"total_logs": 5, "max_id": 5},
		)

		m_order_result = mocker.Mock()
		m_order_result.values_list.return_value = [1, 2]
		m_order = mocker.patch.object(Log.objects, "order_by")
		m_order.return_value = m_order_result

		m_filter = mocker.patch.object(Log.objects, "filter")

		# Execute
		mocker.patch.object(Log, "save")
		log_mixin.log(
			user=test_user,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
		)

		# Verify rotation occurred
		m_filter.assert_called_once_with(id__in=[1, 2])
		m_filter.return_value.delete.assert_called_once()

	def test_log_rotation_not_needed(
		self,
		mocker: MockerFixture,
		log_mixin: LogMixin,
		test_user,
	):
		# Setup
		mocker.patch.object(
			Log.objects,
			"aggregate",
			return_value={"total_logs": 2, "max_id": 2},
		)

		m_order = mocker.patch.object(Log.objects, "order_by")
		m_filter = mocker.patch.object(Log.objects, "filter")

		# Execute
		mocker.patch.object(Log, "save")
		log_mixin.log(
			user=test_user,
			operation_type="TEST_OPERATION",
			log_target_class="TestClass",
		)

		# Verify no rotation occurred
		m_filter.assert_not_called()

	def test_log_atomic_transaction(
		self,
		mocker: MockerFixture,
		log_mixin: LogMixin,
		test_user,
	):
		# Setup
		mocker.patch.object(
			Log.objects, "aggregate", side_effect=Exception("DB error")
		)

		# Execute & Verify
		with pytest.raises(Exception, match="DB error"):
			mocker.patch.object(transaction, "atomic")
			log_mixin.log(
				user=test_user,
				operation_type=LOG_ACTION_UPDATE,
				log_target_class=LOG_CLASS_USER,
			)

	def test_rotate_logs_method(
		self,
		mocker: MockerFixture,
		log_mixin: LogMixin,
	):
		# Setup
		m_order = mocker.patch.object(Log.objects, "order_by")
		m_order.return_value.values_list.return_value = [1, 2, 3]

		m_filter = mocker.patch.object(Log.objects, "filter")

		# Execute
		log_mixin._rotate_logs(
			5, 7
		)  # 7 logs, limit 5, need to remove 3 (7-5+1)

		# Verify
		m_filter.assert_called_once_with(id__in=[1, 2, 3])
		m_filter.return_value.delete.assert_called_once()
