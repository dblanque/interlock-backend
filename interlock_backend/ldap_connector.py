from django_python3_ldap.ldap import Connection
from django.contrib.auth import get_user_model
from django_python3_ldap.utils import import_func, format_search_filter
from django_python3_ldap.conf import settings
from djchoices import C
import interlock_backend.ldap_settings as settings
import logging
import ldap3
from ldap3.core.exceptions import LDAPException

logger = logging.getLogger(__name__)

def open_connection():
    format_username = import_func(settings.LDAP_AUTH_FORMAT_USERNAME)

    # Build server pool
    server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=True, exhaust=5)
    auth_url = settings.LDAP_AUTH_URL
    if not isinstance(auth_url, list):
        auth_url = [auth_url]
    for u in auth_url:
        server_pool.add(
            ldap3.Server(
                u,
                allowed_referral_hosts=[("*", True)],
                get_info=ldap3.NONE,
                connect_timeout=settings.LDAP_AUTH_CONNECT_TIMEOUT,
            )
        )
    # Connect.
    try:
        # Include SSL / TLS, if requested.
        connection_args = {
            "user": settings.LDAP_AUTH_CONNECTION_USER_DN,
            "password": settings.LDAP_AUTH_CONNECTION_PASSWORD,
            "auto_bind": True,
            "raise_exceptions": True,
            "receive_timeout": settings.LDAP_AUTH_RECEIVE_TIMEOUT,
        }
        if settings.LDAP_AUTH_USE_TLS:
            connection_args["tls"] = ldap3.Tls(
                ciphers='ALL',
                version=settings.LDAP_AUTH_TLS_VERSION,
            )
        c = ldap3.Connection(
            server_pool,
            **connection_args,
        )
    except LDAPException as ex:
        logger.warning("LDAP connect failed: {ex}".format(ex=ex))
        return None    
    # Configure.
    try:
        c.bind(read_server_info=True)
        # Perform initial authentication bind.
        # Rebind as specified settings username and password for querying.
        # c.rebind(
        #     user=format_username({settings.LDAP_AUTH_CONNECTION_USERNAME}),
        #     password=settings.LDAP_AUTH_CONNECTION_PASSWORD,
        # )
        # Return the connection.
        logger.info("LDAP connect succeeded")
        return c
    except LDAPException as ex:
        logger.warning("LDAP bind failed: {ex}".format(ex=ex))
        return None
