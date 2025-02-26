
DATABASES = {
    "default": {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'interlockdb',
        'USER': 'interlockadmin',
        'PASSWORD': 'KoenigCc850', # Change this password
        'HOST': '127.0.0.1',  # Or an IP Address that your DB is hosted on
        'PORT': '5432',
    }
}

logging_file_path = "/var/log/interlock/backend.log"

# CORS_ALLOWED_ORIGINS = [
#     "http://localhost:8080",
#     "https://localhost:8080",
# ]
# CSRF_TRUSTED_ORIGINS = [
#     "http://localhost:8080",
#     "https://localhost:8080",
# ]