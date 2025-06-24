from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME

User = get_user_model()
try:
	User.objects.get(username=DEFAULT_SUPERUSER_USERNAME)
except ObjectDoesNotExist:
	User.objects.create_default_superuser()
