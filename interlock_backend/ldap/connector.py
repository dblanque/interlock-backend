# ldap_connector.py
###############################################################################
# Contains:
# - Bind User connector for Administrative Privilege Operations
# - Recursive directory listing functions
###############################################################################
# Originally Created by Dylan Blanqué and BR Consulting S.R.L. (2022)

from django_python3_ldap.ldap import connection as orig_connection
from django_python3_ldap.utils import import_func
from interlock_backend.ldap.encrypt import (
    decrypt,
    encrypt
)
from interlock_backend.ldap.settings_func import (
    SettingsList,
    getSetting
)
import ldap3
from ldap3.core.exceptions import LDAPException
from core.models import Log, User
import ssl
import logging

logger = logging.getLogger(__name__)

def authenticate(*args, **kwargs):
    """
    Authenticates with the LDAP server, and returns
    the corresponding Django user instance.

    The user identifier should be keyword arguments matching the fields
    in settings.LDAP_AUTH_USER_LOOKUP_FIELDS, plus a `password` argument.
    """
    ldap_settings_list = SettingsList(**{"search":{
        'LDAP_AUTH_USER_LOOKUP_FIELDS',
    }})
    password = kwargs.pop("password", None)
    auth_user_lookup_fields = frozenset(ldap_settings_list.LDAP_AUTH_USER_LOOKUP_FIELDS)
    ldap_kwargs = {
        key: value for (key, value) in kwargs.items()
        if key in auth_user_lookup_fields
    }

    encryptedPass = encrypt(password)
    encryptedPass = str(encryptedPass).strip("b'").rstrip("'")

    # Check that this is valid login data.
    if not password or frozenset(ldap_kwargs.keys()) != auth_user_lookup_fields:
        return None

    # Connect to LDAP.
    with orig_connection(password=password, **ldap_kwargs) as c:
        if c is None:
            return None
        user = c.get_user(**ldap_kwargs)
        user.encryptedPassword = encryptedPass
        user.is_local = False
        user.save()
        return user

def openLDAPConnection(
        user_dn=getSetting('LDAP_AUTH_CONNECTION_USER_DN'), 
        password=getSetting('LDAP_AUTH_CONNECTION_PASSWORD'),
        user=None
    ):

    ldap_settings_list = SettingsList(**{"search":{
        'LDAP_AUTH_URL',
        'LDAP_AUTH_CONNECTION_USER_DN',
        'LDAP_AUTH_CONNECTION_PASSWORD',
        'LDAP_AUTH_CONNECT_TIMEOUT',
        'LDAP_AUTH_RECEIVE_TIMEOUT',
        'LDAP_AUTH_USE_TLS',
        'LDAP_AUTH_TLS_VERSION',
        'LDAP_AUTH_FORMAT_USERNAME',
        'LDAP_LOG_OPEN_CONNECTION'
    }})
    ldapAuthURL = ldap_settings_list.LDAP_AUTH_URL
    ldapAuthConnectionPassword = ldap_settings_list.LDAP_AUTH_CONNECTION_PASSWORD
    ldapAuthConnectTimeout = ldap_settings_list.LDAP_AUTH_CONNECT_TIMEOUT
    ldapAuthReceiveTimeout = ldap_settings_list.LDAP_AUTH_RECEIVE_TIMEOUT
    ldapAuthUseTLS = ldap_settings_list.LDAP_AUTH_USE_TLS
    ldapAuthTLSVersion = ldap_settings_list.LDAP_AUTH_TLS_VERSION

    if user is not None:
        if user.username == 'admin' and user.is_local == True:
            user_dn = ldap_settings_list.LDAP_AUTH_CONNECTION_USER_DN
            password = ldapAuthConnectionPassword

    format_username = import_func(ldap_settings_list.LDAP_AUTH_FORMAT_USERNAME)

    logger.debug("Test Connection Endpoint Parameters: ")
    logger.debug(user)
    logger.debug(user_dn)
    logger.debug(password)
    # logger.debug(ldapAuthConnectionPassword)
    logger.debug(ldapAuthURL)
    logger.debug(ldapAuthConnectTimeout)
    logger.debug(ldapAuthReceiveTimeout)
    logger.debug(ldapAuthUseTLS)
    logger.debug(ldapAuthTLSVersion)

    if password != ldapAuthConnectionPassword:
        password = str(decrypt(password))

    # Build server pool
    server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=True, exhaust=5)
    auth_url = ldapAuthURL
    if not isinstance(auth_url, list):
        auth_url = [auth_url]
    for u in auth_url:
        server_pool.add(
            ldap3.Server(
                u,
                allowed_referral_hosts=[("*", True)],
                get_info=ldap3.NONE,
                connect_timeout=ldapAuthConnectTimeout,
            )
        )
    # Connect.
    try:
        # LOG Open Connection Events
        if user is not None and ldap_settings_list.LDAP_LOG_OPEN_CONNECTION == True:
            logAction = Log(
                user_id=user.id,
                actionType="OPEN",
                objectClass="CONN"
            )
            logAction.save()
        # Include SSL / TLS, if requested.
        connection_args = {
            "user": user_dn,
            "password": password,
            "auto_bind": True,
            "raise_exceptions": True,
            "receive_timeout": ldapAuthReceiveTimeout,
        }
        if ldapAuthUseTLS:
            connection_args["tls"] = ldap3.Tls(
                ciphers='ALL',
                version=ldapAuthTLSVersion,
            )
        c = ldap3.Connection(
            server_pool,
            **connection_args,
        )
    except LDAPException as ex:
        logger.warning("LDAP connect failed: {ex}".format(ex=ex))
        return None

    # ! Unset Password ! #
    password = ""
    # Configure.
    try:
        c.bind(read_server_info=True)
        # Perform initial authentication bind.
        # Rebind as specified settings username and password for querying.
        # c.rebind(
        #     user=format_username({username}),
        #     password=password,
        # )
        # Return the connection.
        logger.debug("LDAP connect for user " + user_dn + " succeeded")
        return c
    except LDAPException as ex:
        logger.warning("LDAP bind failed: {ex}".format(ex=ex))
        return None

def testLDAPConnection(
        username,
        user_dn, # Actually this is user_dn
        password,
        ldapAuthConnectionUser,
        ldapAuthConnectionPassword,
        ldapAuthURL,
        ldapAuthConnectTimeout,
        ldapAuthReceiveTimeout,
        ldapAuthUseTLS,
        ldapAuthTLSVersion
    ):
    ldap_settings_list = SettingsList(**{"search":{
        'LDAP_AUTH_FORMAT_USERNAME'
    }})
    format_username = import_func(ldap_settings_list.LDAP_AUTH_FORMAT_USERNAME)

    if password != ldapAuthConnectionPassword and username != 'admin':
        password = str(decrypt(password))
    elif username == 'admin':
        user_dn = ldapAuthConnectionUser
        password = ldapAuthConnectionPassword

    if not isinstance(ldapAuthConnectTimeout, int):
        logger.info('ldapAuthConnectTimeout is not an int, using default')
        ldapAuthConnectTimeout = 5
    if not isinstance(ldapAuthReceiveTimeout, int):
        logger.info('ldapAuthReceiveTimeout is not an int, using default')
        ldapAuthReceiveTimeout = 5

    # Build server pool
    server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=True, exhaust=5)
    auth_url = ldapAuthURL
    if not isinstance(auth_url, list):
        auth_url = [auth_url]
    for u in auth_url:
        server_pool.add(
            ldap3.Server(
                u,
                allowed_referral_hosts=[("*", True)],
                get_info=ldap3.NONE,
                connect_timeout=ldapAuthConnectTimeout,
            )
        )
    # Connect.
    try:
        # Include SSL / TLS, if requested.
        connection_args = {
            "user": user_dn,
            "password": password,
            "auto_bind": True,
            "raise_exceptions": True,
            "receive_timeout": ldapAuthReceiveTimeout,
        }
        if ldapAuthUseTLS:
            connection_args["tls"] = ldap3.Tls(
                ciphers='ALL',
                version=getattr(ssl, ldapAuthTLSVersion),
            )
        c = ldap3.Connection(
            server_pool,
            **connection_args,
        )
    except LDAPException as ex:
        logger.warning("LDAP connect failed: {ex}".format(ex=ex))
        return None

    # ! Unset Password ! #
    password = ""
    # Configure.
    try:
        c.bind(read_server_info=True)
        # Perform initial authentication bind.
        # Rebind as specified settings username and password for querying.
        # c.rebind(
        #     user=format_username({username}),
        #     password=password,
        # )
        # Return the connection.
        logger.debug("LDAP connect for user " + user_dn + " succeeded")
        return c
    except LDAPException as ex:
        logger.warning("LDAP bind failed: {ex}".format(ex=ex))
        return None
