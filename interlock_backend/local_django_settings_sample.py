# pragma: no cover
# File: interlock_backend/local_django_settings_sample.py
# Any option in interlock_backend.settings can be overridden here.

# If you want to debug
# DEBUG = True or False

DATABASES = {
	"default": {
		"ENGINE": "django.db.backends.postgresql",
		"NAME": "SomeDatabase",
		"USER": "SomeUser",
		"PASSWORD": "SomePassword",  # Change this password
		"HOST": "127.0.0.1",  # Or an IP Address that your DB is hosted on
		"PORT": "5432",
	}
}

FRONT_URL = "interlock.example.com"

# CORS and CSRF overrides
# CORS_ALLOWED_ORIGINS = [
# 	# ! DEV
# 	"http://127.0.0.1",
# 	# PRODUCTION
# 	f"http://{FRONT_URL}",
# 	f"https://{FRONT_URL}",
# ]
# CSRF_TRUSTED_ORIGINS = [
# 	# ! DEV
# 	"http://127.0.0.1",
# 	# PRODUCTION
# 	f"http://{FRONT_URL}",
# 	f"https://{FRONT_URL}",
# ]
