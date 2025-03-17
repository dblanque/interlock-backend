from .settings import *

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
