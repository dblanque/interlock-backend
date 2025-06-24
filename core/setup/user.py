from core.models.user import User
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME
from core.utils.db import db_table_exists


def create_default_superuser():
	if not db_table_exists("core_user"):
		return
	if (
		not User.objects.get_full_queryset()
		.filter(username=DEFAULT_SUPERUSER_USERNAME)
		.exists()
	):
		User.objects.create_default_superuser()
