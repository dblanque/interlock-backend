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
from core.views.mixins.utils import testPort

### Others
from interlock_backend.ldap.connector import testLDAPConnection
import logging
################################################################################

logger = logging.getLogger(__name__)

class SettingsViewMixin(viewsets.ViewSetMixin):

    def getAdminStatus(self):
        userQuerySet = User.objects.filter(username = 'admin')
        if userQuerySet.count() > 0:
            status = userQuerySet.get(username = 'admin').deleted
            return not status
        else:
            return False

    @transaction.atomic
    def setAdminStatus(self, status, password=None):
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

    @transaction.atomic
    def resetSettings(self):
        # Deletes all setting overrides in DB
        [setting.delete_permanently() for setting in Setting.objects.all()]
        return True

    def testSettings(self, user, data):
        if user == None:
            raise exc_user.UserPermissionError

        ldapAuthConnectionUser = data['LDAP_AUTH_CONNECTION_USER_DN']['value']
        ldapAuthConnectionPassword = data['LDAP_AUTH_CONNECTION_PASSWORD']['value']
        ldapAuthURL = data['LDAP_AUTH_URL']['value']
        ldapAuthConnectTimeout = int(data['LDAP_AUTH_CONNECT_TIMEOUT']['value'])
        ldapAuthReceiveTimeout = int(data['LDAP_AUTH_RECEIVE_TIMEOUT']['value'])
        ldapAuthUseTLS = data['LDAP_AUTH_USE_TLS']['value']
        ldapAuthTLSVersion = data['LDAP_AUTH_TLS_VERSION']['value']

        logger.info("LDAP Socket Testing")
        for server in ldapAuthURL:
            ip = server.split(":")[1][2:]
            port = server.split(":")[2]
            logger.info("IP to Test: " + ip)
            logger.info("Port to Test: " + port)
            if not testPort(ip, port, ldapAuthConnectTimeout):
                exception = exc_ldap.PortUnreachable
                data = {
                    "code": "ldap_port_err",
                    "ipAddress": ip,
                    "port": port,
                }
                exception.setDetail(exception, data)
                raise exception
            logger.info("Test successful")

        username = user.username
        if username == "admin":
            user_dn = ldapAuthConnectionUser
        else:
            user_dn = user.dn

        logger.info("Test Connection Endpoint Parameters: ")
        logger.info(username)
        logger.info(user_dn)
        logger.info(user.encryptedPassword)
        logger.info(ldapAuthConnectionUser)
        # logger.info(ldapAuthConnectionPassword)
        logger.info(ldapAuthURL)
        logger.info(ldapAuthConnectTimeout)
        logger.info(ldapAuthReceiveTimeout)
        logger.info(ldapAuthUseTLS)
        logger.info(ldapAuthTLSVersion)

        # Open LDAP Connection
        try:
            c = testLDAPConnection(
                username = username,
                user_dn = user_dn,
                password = user.encryptedPassword,
                ldapAuthConnectionUser = ldapAuthConnectionUser,
                ldapAuthConnectionPassword = ldapAuthConnectionPassword,
                ldapAuthURL = ldapAuthURL,
                ldapAuthConnectTimeout = ldapAuthConnectTimeout,
                ldapAuthReceiveTimeout = ldapAuthReceiveTimeout,
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
        result['tls'] = ldapAuthUseTLS
        result['tls_version'] = ldapAuthTLSVersion
        logger.info("Test Connection Endpoint Result: ")
        logger.info(result)
        return result
