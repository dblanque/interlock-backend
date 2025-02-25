from django.contrib.auth import get_user_model
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME

User = get_user_model()
if User.objects.filter(username=DEFAULT_SUPERUSER_USERNAME).count() > 0:
    def_superuser = User.objects.get(username=DEFAULT_SUPERUSER_USERNAME)
    def_superuser.delete_permanently()

User.objects.create_default_superuser()
