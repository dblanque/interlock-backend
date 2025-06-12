from core.models.user import User
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME
from core.utils.db import db_table_exists


def create_default_superuser():
	if not db_table_exists("core_user"):
		return
	if User.objects\
		.get_full_queryset()\
		.filter(username=DEFAULT_SUPERUSER_USERNAME)\
		.count() == 0:
		User.objects.create_default_superuser()
