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
from interlock_backend.ldap.constants import *
from interlock_backend.local_django_settings import *
import base64

# A little easter egg for you :)
# from this import d

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'in2tfy@bhej(5i@h!_04+kes__58rd9mh$=1!o_6ky236d-ue)'

# Dynamic Encrypt / Decrypt KEY, changes when the app is restarted
# ALL users will loose their sessions when this happens.
# ! MAKE IT DYNAMIC WHEN IN PRODUCTION
# FERNET_KEY = base64.urlsafe_b64encode(os.urandom(32))
FERNET_KEY = b'7HWX7ZH2k-7KrdPkCtaAC8lAjZ8gaz0HrJTeWTthm24='

DJANGO_SUPERUSER_USERNAME = 'admin'
DJANGO_SUPERUSER_PASSWORD = 'interlock'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOW_ALL_HOSTS = ['*']

# Allows requests from all origins.
# If this is used then `CORS_ORIGIN_WHITELIST` will not have any effect
if DEBUG == True:
    CORS_ORIGIN_ALLOW_ALL = True
    CORS_ALLOW_CREDENTIALS = True
    ALLOWED_HOSTS = ALLOW_ALL_HOSTS # CHANGE ON PRODUCTION
else:
    ALLOWED_HOSTS = ['127.0.0.1']

# If this is used, then not need to use `CORS_ORIGIN_ALLOW_ALL = True`
#CORS_ORIGIN_WHITELIST = [
#    'http://localhost:3030',
#] 
#CORS_ORIGIN_REGEX_WHITELIST = [
#    'http://localhost:3030',
#]

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
    "rest_framework.authtoken",
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

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "loggers": {
        "django_python3_ldap": {
            "handlers": ["console"],
            "level": "INFO",
        },
        "interlock_backend.ldap.connector": {
            "handlers": ["console"],
            "level": "INFO",
        },
        "core.models.dns": {
            "handlers": ["console"],
            "level": "INFO",
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
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        #~~~~ Uncomment to allow authentication "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "DEFAULT_PERMISSION_CLASSES": [
        #~~~~"rest_framework.permissions.IsAuthenticated"
    ],
    "PAGE_SIZE": 10,
}

DATE_INPUT_FORMATS = ['%Y-%m-%d']

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5), # Change for development (default was minutes=5)
    'REFRESH_TOKEN_LIFETIME': timedelta(minutes=15),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': False,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY, #May be changed into an independent key for JWT, in order to make it more modular
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JWK_URL': None,
    'LEEWAY': 0,

    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
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

TIME_ZONE = 'UTC'

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