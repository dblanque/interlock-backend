import pytest
from pytest_mock import MockType
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

@pytest.fixture
def log_mixin():
	return LogMixin()

@pytest.fixture
def test_user():
	return User.objects.create_user(
		username="testuser",
		password="testpass",
		email="test@example.com"
	)

@pytest.fixture
def f_runtime_settings(g_runtime_settings):
	g_runtime_settings.LDAP_LOG_MAX = 5
	return g_runtime_settings

@pytest.mark.django_db
class TestLogMixin:
	def test_log_with_invalid_operation_type(self, log_mixin: LogMixin, test_user, f_runtime_settings, mocker):
		# Setup
		m_logger = mocker.patch("core.views.mixins.logs.logger")

		# Execute
		result = log_mixin.log(
			user=test_user,
			operation_type="TEST_OPERATION",
			log_target_class="TestClass"
		)
		
		# Verify
		assert result is None
		m_logger.warning.assert_called_once_with(
			"RuntimeSettings does not have the %s attribute.", "LDAP_LOG_TEST_OPERATION"
		)

	def test_log_with_invalid_user_type(self, log_mixin: LogMixin, f_runtime_settings):		
		# Execute & Verify
		with pytest.raises(TypeError, match="user must be of type int | User"):
			log_mixin.log(
				user="invalid_user",
				operation_type=LOG_ACTION_READ,
				log_target_class=LOG_CLASS_USER
			)

	def test_log_with_user_object(self, log_mixin: LogMixin, test_user, f_runtime_settings, mocker):
		# Setup
		mocker.patch.object(Log.objects, 'aggregate', return_value={'total_logs': 0, 'max_id': 0})
		mocker.patch.object(Log.objects, 'order_by')
		mocker.patch.object(Log.objects, 'filter')

		# Execute
		m_save: MockType = mocker.patch.object(Log, 'save')
		log_mixin.log(
			user=test_user,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER,
			message=LOG_EXTRA_USER_END_USER_UPDATE
		)

		# Verify
		m_save.assert_called_once()

	def test_log_with_user_id(self, log_mixin: LogMixin, test_user, f_runtime_settings, mocker):
		# Setup
		mocker.patch.object(Log.objects, 'aggregate', return_value={'total_logs': 0, 'max_id': 0})
		mocker.patch.object(Log.objects, 'order_by')
		mocker.patch.object(Log.objects, 'filter')
		
		# Execute
		m_save: MockType = mocker.patch.object(Log, 'save')
		log_mixin.log(
			user=test_user.id,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER
		)
		
		# Verify
		assert m_save.called

	def test_log_rotation_needed(self, log_mixin: LogMixin, test_user, f_runtime_settings, mocker):
		# Setup
		f_runtime_settings.LDAP_LOG_MAX = 3
		mocker.patch.object(Log.objects, 'aggregate', return_value={'total_logs': 5, 'max_id': 5})
		
		m_order = mocker.patch.object(Log.objects, 'order_by')
		m_order.return_value.values_list.return_value = [1, 2]
		
		m_filter = mocker.patch.object(Log.objects, 'filter')
		
		# Execute
		mocker.patch.object(Log, 'save')
		log_mixin.log(
			user=test_user,
			operation_type=LOG_ACTION_UPDATE,
			log_target_class=LOG_CLASS_USER
		)
		
		# Verify rotation occurred
		m_filter.assert_called_once_with(id__in=[1, 2])
		m_filter.return_value.delete.assert_called_once()

	def test_log_rotation_not_needed(self, log_mixin: LogMixin, test_user, f_runtime_settings, mocker):
		# Setup
		mocker.patch.object(Log.objects, 'aggregate', return_value={'total_logs': 2, 'max_id': 2})
		
		m_order = mocker.patch.object(Log.objects, 'order_by')
		m_filter = mocker.patch.object(Log.objects, 'filter')
		
		# Execute
		mocker.patch.object(Log, 'save')
		log_mixin.log(
			user=test_user,
			operation_type="TEST_OPERATION",
			log_target_class="TestClass"
		)
		
		# Verify no rotation occurred
		m_filter.assert_not_called()

	def test_log_atomic_transaction(self, log_mixin: LogMixin, test_user, f_runtime_settings, mocker):
		# Setup
		mocker.patch.object(Log.objects, 'aggregate', side_effect=Exception("DB error"))

		# Execute & Verify
		with pytest.raises(Exception, match="DB error"):
			mocker.patch.object(transaction, 'atomic')
			log_mixin.log(
				user=test_user,
				operation_type=LOG_ACTION_UPDATE,
				log_target_class=LOG_CLASS_USER
			)

	def test_rotate_logs_method(self, log_mixin: LogMixin, mocker):
		# Setup
		m_order = mocker.patch.object(Log.objects, 'order_by')
		m_order.return_value.values_list.return_value = [1, 2, 3]
		
		m_filter = mocker.patch.object(Log.objects, 'filter')
		
		# Execute
		log_mixin._rotate_logs(5, 7)  # 7 logs, limit 5, need to remove 3 (7-5+1)
		
		# Verify
		m_filter.assert_called_once_with(id__in=[1, 2, 3])
		m_filter.return_value.delete.assert_called_once()
