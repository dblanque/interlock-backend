from django.contrib.auth import get_user_model
from interlock_backend.settings import DJANGO_SUPERUSER_USERNAME

User = get_user_model()
if not User.objects.get(username=DJANGO_SUPERUSER_USERNAME):
    User.objects.create_default_superuser()
