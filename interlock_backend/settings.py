"""
Django settings for interlock_backend project.

Generated by 'django-admin startproject' using Django 3.0.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import os
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _
from datetime import timedelta
from interlock_backend.local_django_settings import *
import base64
from importlib import util as importutils
import mimetypes
mimetypes.add_type("text/css", ".css", True)
from django.core.management.utils import get_random_secret_key  
# Force Process Reload through file saving.
from interlock_backend.reload import STUB_RELOAD

# A little easter egg for you :)
# from this import d

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret and fernet keys used in production secret!
SECRET_KEY = None
FERNET_KEY = None

secretFile = BASE_DIR+'/interlock_backend/sec_key.py'
sec_spec = importutils.find_spec("interlock_backend.sec_key", package="sec_spec")
if sec_spec is not None:
    from interlock_backend import sec_key
    if 'SECRET_KEY' in sec_key.__dict__ and sec_key.SECRET_KEY is not None and len(sec_key.SECRET_KEY) > 0:
        SECRET_KEY = sec_key.SECRET_KEY

if SECRET_KEY is None or len(str(SECRET_KEY)) < 1:
    SECRET_KEY = get_random_secret_key()
    # Write the file
    with open(secretFile, 'w') as file:
        file.write("SECRET_KEY = " + str(SECRET_KEY))

if SECRET_KEY is None or len(str(SECRET_KEY)) < 1:
    raise ImproperlyConfigured("Secret Key is invalid (None or len < 1)")

# Decryption KEY, this is automatically generated in relative path:
# - interlock_backend/enc_key.py
# ! If the key changes you will need to re-save your LDAP Bind Password
# ! and all your users will be required to login again
# To MANUALLY generate a new key run this code in python and paste the return value into enc_key.py
# python3 <<< "import base64; import os; key = base64.urlsafe_b64encode(os.urandom(32)); print(key)"
# FERNET_KEY = base64.urlsafe_b64encode(os.urandom(32))

FERNET_KEY = None
fernetFile = BASE_DIR+'/interlock_backend/enc_key.py'
enc_spec = importutils.find_spec("interlock_backend.enc_key", package="enc_spec")
if enc_spec is not None:
    from interlock_backend import enc_key
    if 'FERNET_KEY' in enc_key.__dict__ and enc_key.FERNET_KEY is not None and len(enc_key.FERNET_KEY) > 0:
        FERNET_KEY = enc_key.FERNET_KEY

if FERNET_KEY is None or len(str(FERNET_KEY)) < 1:
    FERNET_KEY = base64.urlsafe_b64encode(os.urandom(32))
    # Write the file
    with open(fernetFile, 'w') as file:
        file.write("FERNET_KEY = " + str(FERNET_KEY))

if FERNET_KEY is None or len(str(FERNET_KEY)) < 1:
    raise ImproperlyConfigured("Fernet Key is invalid (None or len < 1)")

# Default admin username and password
DJANGO_SUPERUSER_USERNAME = 'admin'
DJANGO_SUPERUSER_PASSWORD = 'interlock'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# ! ALWAYS LEAVE THIS ON TRUE
CORS_ALLOW_CREDENTIALS = True
DEV_URL = "http://127.0.0.1:3000"
FRONT_URL = DEV_URL
URLS = [ DEV_URL ]
if FRONT_URL != DEV_URL:
    URLS.append(f"http://{FRONT_URL}")
    URLS.append(f"https://{FRONT_URL}")

# If you want to restrict to a subnet or host
# ALLOWED_HOSTS = ['127.0.0.1']
ALLOW_ALL_HOSTS = ['*']
if DEBUG:
    # If this is used then `CORS_ORIGIN_WHITELIST` will not have any effect
    # Allows requests from all origins.
    CORS_ORIGIN_ALLOW_ALL = True
    ALLOWED_HOSTS = ALLOW_ALL_HOSTS
else:
    # SAFE CORS SETTINGS
    # If this is used, there's no need to use `CORS_ORIGIN_ALLOW_ALL = True`
    CORS_ALLOWED_ORIGINS = URLS
    CORS_ORIGIN_WHITELIST = URLS
    CORS_ORIGIN_REGEX_WHITELIST = URLS
    ALLOWED_HOSTS = [ 'localhost', '127.0.0.1', FRONT_URL ]

# Application definition

INSTALLED_APPS = [
    "sslserver",
    "django_extensions",
    "django.contrib.admin",
    "django.contrib.auth",
    "django_python3_ldap",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_otp",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_hotp",
    "django_otp.plugins.otp_static",
    "rest_framework",
    "drf_yasg",
    "corsheaders",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    'django.middleware.locale.LocaleMiddleware',
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",  # Must be before Common Middleware
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
	"django_otp.middleware.OTPMiddleware", # Must be after Authentication Middleware
]

ROOT_URLCONF = 'interlock_backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'interlock_backend.wsgi.application'

AUTHENTICATION_BACKENDS = (
    "django.contrib.auth.backends.ModelBackend", # Comment if you wish to use LDAP Auth Only
    "interlock_backend.ldap.auth.LDAPBackend",
    # "django_python3_ldap.auth.LDAPBackend",
    )

AUTH_USER_MODEL = "core.User"

LOG_FILE_FOLDER = f'{BASE_DIR}/logs'
LOG_FILE_PATH = f'{LOG_FILE_FOLDER}/interlock.drf.log'

if not os.path.exists(LOG_FILE_FOLDER):
    os.makedirs(LOG_FILE_FOLDER)

if not os.path.exists(LOG_FILE_PATH):
    LOG_EXISTS = open(LOG_FILE_PATH, "w")
    LOG_EXISTS.close()

if not LOG_FILE_PATH:
    raise ImproperlyConfigured("No LOG_FILE_PATH found.")

LOG_LEVEL = "INFO"
LDAP3_MODULE_LOG_LEVEL = "WARNING"
LDAP_CONNECTOR_LOG_LEVEL = "INFO"
LDAP_DNS_LOG_LEVEL = "WARNING"
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    'formatters': {
        'timestamp': {
            'format': '{asctime} [{levelname}] - {message}',
            'style': '{',
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
        'file': {
            'level': "WARNING",
            'class': "logging.FileHandler",
            'formatter': 'timestamp',
            'filename': LOG_FILE_PATH
        }
    },
    "loggers": {
        '': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
        },
        "django_python3_ldap": {
            "level": LDAP3_MODULE_LOG_LEVEL,
        },
        "interlock_backend.ldap.connector": {
            "level": LDAP_CONNECTOR_LOG_LEVEL,
        },
        "core.models.dns": {
            "level": LDAP_DNS_LOG_LEVEL,
        },
    },
}

# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases

if not DATABASES:
    DATABASES = {
        "default": {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': 'interlockdb',
            'USER': 'interlockadmin',
            'PASSWORD': 'Clave1234', # Change this password
            'HOST': '127.0.0.1',  # Or an IP Address that your DB is hosted on
            'PORT': '5432',
        },
        'test': {
            'NAME': f"test_interlockdb",
        }
    }

# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

REST_FRAMEWORK = {
    "COERCE_DECIMAL_TO_STRING": False,
    "EXCEPTION_HANDLER": 'core.system.exceptionhandler.custom_exception_handler',
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "core.views.mixins.auth.CookieJWTAuthentication",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 10,
}

DATE_INPUT_FORMATS = ['%Y-%m-%d']

BAD_LOGIN_COOKIE_NAME="X_BAD_LOGIN_COUNT"
SIMPLE_JWT = {
    # Change for development (default is minutes=5)
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(minutes=15),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': False,
    'UPDATE_LAST_LOGIN': False,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY, #May be changed into an independent key for JWT, in order to make it more modular
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JWK_URL': None,
    'LEEWAY': 1,

    ######################## AUTH TOKEN COOKIE ########################
    'AUTH_HEADER_NAME': 'HTTP_COOKIE',
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_COOKIE_DOMAIN': None,
    'AUTH_COOKIE_NAME': 'access_token',
    'REFRESH_COOKIE_NAME': 'refresh_token',
    'AUTH_COOKIE_SECURE': False if DEBUG == True else True,
    'AUTH_COOKIE_HTTP_ONLY' : True,
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value
    # 'AUTH_COOKIE_SAME_SITE': 'lax',
    'AUTH_COOKIE_SAME_SITE': 'strict',
    ###################################################################
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',

    'JTI_CLAIM': 'jti',

    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
}

# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

# Get current System Olson Timezone
try: TIME_ZONE = '/'.join(os.readlink('/etc/timezone').split('/')[-2:])
except: TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATIC_URL = '/static/'

# --- Email settings ---
EMAIL_HOST = ""
EMAIL_PORT = 587
EMAIL_HOST_USER = ""
EMAIL_HOST_PASSWORD = "NOUSERYET"
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False #Note that TLS and SSL are mutually exclusive, both can NOT be simultaneously True.
EMAIL_TIMEOUT = 30
EMAIL_SSL_KEYFILE = None
EMAIL_SSL_CERTFILE = None
PUBLIC_STAFF_EMAIL = ""