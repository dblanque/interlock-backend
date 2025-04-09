import pytest
from django.db import transaction
from core.models.log import Log
from core.views.mixins.logs import LogMixin

@pytest.fixture
def log_mixin():
    return LogMixin()

@pytest.mark.django_db
class TestLogMixin:
    def test_log_creation_below_limit(self, log_mixin: LogMixin, g_runtime_settings):
        # Setup
        g_runtime_settings.LDAP_LOG_MAX = 10
        
        # Test
        log_id = log_mixin.log(message="Test message")
        
        # Verify
        assert Log.objects.count() == 1
        assert Log.objects.filter(id=log_id).exists()

    def test_log_rotation_at_limit(self, log_mixin: LogMixin, g_runtime_settings):
        # Setup
        g_runtime_settings.LDAP_LOG_MAX = 3
        # Create 3 existing logs
        for i in range(3):
            Log.objects.create(message=f"Old log {i}")
        
        # Test
        new_log_id = log_mixin.log(message="New log")
        
        # Verify
        assert Log.objects.count() == 3  # Should maintain limit
        assert not Log.objects.filter(message__startswith="Old log 0").exists()
        assert Log.objects.filter(id=new_log_id).exists()

    def test_log_rotation_above_limit(self, log_mixin: LogMixin, g_runtime_settings):
        # Setup
        g_runtime_settings.LDAP_LOG_MAX = 2
        # Create 3 existing logs
        for i in range(3):
            Log.objects.create(message=f"Old log {i}")
        
        # Test
        new_log_id = log_mixin.log(message="New log")
        
        # Verify
        assert Log.objects.count() == 2  # Should enforce limit
        assert not Log.objects.filter(message__startswith="Old log 0").exists()
        assert not Log.objects.filter(message__startswith="Old log 1").exists()
        assert Log.objects.filter(id=new_log_id).exists()

    def test_atomic_operations(self, log_mixin: LogMixin, mocker, g_runtime_settings):
        # Setup
        g_runtime_settings.LDAP_LOG_MAX = 1
        mocker.patch.object(Log.objects, 'delete', side_effect=Exception("DB error"))
        
        # Test & Verify
        with pytest.raises(Exception):
            with transaction.atomic():
                log_mixin.log(message="Should rollback")
        
        assert Log.objects.count() == 0  # Verify no changes persisted
