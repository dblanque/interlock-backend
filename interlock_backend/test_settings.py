from .settings import *
from datetime import timedelta

TEST_DB_NAME = "test_interlockdb"
DATABASES = {
	"default": {
		"ENGINE": "django.db.backends.postgresql",
		"NAME": TEST_DB_NAME,
		"USER": "test_interlockadmin",
		"PASSWORD": "Clave1234",  # Change this password
		"HOST": "127.0.0.1",  # Or an IP Address that your DB is hosted on
		"PORT": "5432",
		"TEST": {
			"NAME": TEST_DB_NAME,  # Use a custom test database name
		},
	}
}
SIMPLE_JWT = SIMPLE_JWT | {
	"ACCESS_TOKEN_LIFETIME": timedelta(hours=1),  # Longer for tests
	"REFRESH_TOKEN_LIFETIME": timedelta(days=1),
	"AUTH_COOKIE_SECURE": True,
}
LDAP_CONNECTOR_PYTEST_MODE = True
ENABLE_THROTTLING = False
for k in ("DEFAULT_THROTTLE_CLASSES", "DEFAULT_THROTTLE_RATES"):
	if k in REST_FRAMEWORK:
		del REST_FRAMEWORK[k]

SCHEDULER_LDAP_REF_ENABLE = False
