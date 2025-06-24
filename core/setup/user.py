from core.models.user import User
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME
from core.utils.db import db_table_exists
from django.core.exceptions import ObjectDoesNotExist


def create_default_superuser():
	if not db_table_exists("core_user"):
		return
	try:
		User.objects.get(username=DEFAULT_SUPERUSER_USERNAME)
	except ObjectDoesNotExist:
		User.objects.create_default_superuser()
