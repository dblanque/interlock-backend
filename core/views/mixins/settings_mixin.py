################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.settings_mixin
# Contains the Mixin for Setting related operations

#---------------------------------- IMPORTS -----------------------------------#
### Django
from django.db import transaction

### ViewSets
from rest_framework import viewsets

### Core
#### Models
from core.models.user import User

#### Exceptions
from core.exceptions import (
    ldap as exc_ldap,
    users as exc_user
)

#### Mixins
from core.views.mixins.utils import net_port_test

### Others
from interlock_backend.ldap.connector import test_ldap_connection
from interlock_backend.settings import BASE_DIR
import logging
################################################################################

logger = logging.getLogger(__name__)

class SettingsViewMixin(viewsets.ViewSetMixin):

    def restart_django(self):
        reloader = BASE_DIR+'/interlock_backend/reload.py'
        # Write the file
        with open(reloader, 'w') as file:
            file.write("STUB_RELOAD = False")

    def get_admin_status(self):
        userQuerySet = User.objects.filter(username = 'admin')
        if userQuerySet.count() > 0:
            status = userQuerySet.get(username = 'admin').deleted
            return not status
        else:
            return False

    @transaction.atomic
    def set_admin_status(self, status, password=None):
        userQuerySet = User.objects.get_full_queryset().filter(username = 'admin')
        if status == True and userQuerySet.count() == 0:
            defaultAdmin = User.objects.create_default_superuser()

        if userQuerySet.count() > 0:
            defaultAdmin = userQuerySet.get(username = 'admin')
            defaultAdmin.deleted = not status
            defaultAdmin.save()

        if password and password != "":
            defaultAdmin.set_password(password)
            defaultAdmin.save()

    def test_ldap_settings(self, user, data):
        if user == None:
            raise exc_user.UserPermissionError

        ldapAuthConnectionUser = data['LDAP_AUTH_CONNECTION_USER_DN']['value']
        ldapAuthConnectionPassword = data['LDAP_AUTH_CONNECTION_PASSWORD']['value']
        ldapAuthURL = data['LDAP_AUTH_URL']['value']
        ldapAuthConnectTimeout = int(data['LDAP_AUTH_CONNECT_TIMEOUT']['value'])
        ldapAuthReceiveTimeout = int(data['LDAP_AUTH_RECEIVE_TIMEOUT']['value'])
        ldapAuthUseSSL = data['LDAP_AUTH_USE_SSL']['value']
        ldapAuthUseTLS = data['LDAP_AUTH_USE_TLS']['value']
        ldapAuthTLSVersion = data['LDAP_AUTH_TLS_VERSION']['value']

        logger.info("LDAP Socket Testing")
        for server in ldapAuthURL:
            ip = server.split(":")[1][2:]
            port = server.split(":")[2]
            logger.info("IP to Test: " + ip)
            logger.info("Port to Test: " + port)
            if not net_port_test(ip, port, ldapAuthConnectTimeout):
                exception = exc_ldap.PortUnreachable
                data = {
                    "code": "ldap_port_err",
                    "ipAddress": ip,
                    "port": port,
                }
                exception.set_detail(exception, data)
                raise exception
            logger.info("Test successful")

        username = user.username
        if username == "admin":
            user_dn = ldapAuthConnectionUser
        else:
            user_dn = user.dn

        logger.info("Test Connection Endpoint Parameters: ")
        logger.info(f'User: {username}')
        logger.info(f'User DN: {user_dn}')
        logger.info(f'LDAP Connection User: {ldapAuthConnectionUser}')
        # logger.info(ldapAuthConnectionPassword)
        logger.info(f'LDAP URL: {ldapAuthURL}')
        logger.info(f'LDAP Connect Timeout: {ldapAuthConnectTimeout}')
        logger.info(f'LDAP Receive Timeout: {ldapAuthReceiveTimeout}')
        logger.info(f'Force SSL: {ldapAuthUseSSL}')
        logger.info(f'Use TLS: {ldapAuthUseTLS}')
        logger.info(f'TLS Version: {ldapAuthTLSVersion}')

        # Open LDAP Connection
        try:
            c = test_ldap_connection(
                username = username,
                user_dn = user_dn,
                password = user.encryptedPassword,
                ldapAuthConnectionUser = ldapAuthConnectionUser,
                ldapAuthConnectionPassword = ldapAuthConnectionPassword,
                ldapAuthURL = ldapAuthURL,
                ldapAuthConnectTimeout = ldapAuthConnectTimeout,
                ldapAuthReceiveTimeout = ldapAuthReceiveTimeout,
                ldapAuthUseSSL = ldapAuthUseSSL,
                ldapAuthUseTLS = ldapAuthUseTLS,
                ldapAuthTLSVersion = ldapAuthTLSVersion,
                )
        except Exception as e:
            print(e)
            raise exc_ldap.CouldNotOpenConnection

        result = c.result
        c.unbind()

        result['user_used'] = username
        result['user_dn_used'] = user_dn
        result['server_pool'] = ldapAuthURL
        result['ssl'] = ldapAuthUseSSL
        result['tls'] = ldapAuthUseTLS
        result['tls_version'] = ldapAuthTLSVersion
        logger.info("Test Connection Endpoint Result: ")
        logger.info(result)
        return result
