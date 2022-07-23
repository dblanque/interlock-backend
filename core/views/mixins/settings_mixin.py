from rest_framework import viewsets
from core.models.settings_model import Setting
from core.models.user import User
from django.db import transaction
from interlock_backend.ldap.connector import open_connection, test_connection
from interlock_backend.ldap.settings_func import normalizeValues
from core.exceptions import ldap as ldap_exceptions
from core.exceptions import users as user_exceptions
from core.views.mixins.utils import testPort
import logging
import re
import json

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
            raise user_exceptions.UserPermissionError

        ldapAuthConnectionUser = data['LDAP_AUTH_CONNECTION_USER_DN']['value']
        ldapAuthConnectionPassword = data['LDAP_AUTH_CONNECTION_PASSWORD']['value']
        ldapAuthURL = data['LDAP_AUTH_URL']['value']
        ldapAuthConnectTimeout = int(data['LDAP_AUTH_CONNECT_TIMEOUT']['value'])
        ldapAuthReceiveTimeout = int(data['LDAP_AUTH_RECEIVE_TIMEOUT']['value'])
        ldapAuthUseTLS = data['LDAP_AUTH_USE_TLS']['value']
        ldapAuthTLSVersion = data['LDAP_AUTH_TLS_VERSION']['value']

        logger.debug("LDAP Socket Testing")
        for server in ldapAuthURL:
            ip = server.split(":")[1][2:]
            port = server.split(":")[2]
            logger.debug("IP to Test: " + ip)
            logger.debug("Port to Test: " + port)
            if not testPort(ip, port, ldapAuthConnectTimeout):
                exception = ldap_exceptions.PortUnreachable
                data = {
                    "data" : {
                        "code": "ldap_port_err",
                        "ipAddress": ip,
                        "port": port,
                    }
                }
                exception.setDetail(exception, data)
                raise exception
            logger.debug("Test successful")

        username = user.username
        if username == "admin":
            user_dn = ldapAuthConnectionUser
        else:
            user_dn = user.dn

        logger.debug("Test Connection Endpoint Parameters: ")
        logger.debug(username)
        logger.debug(user_dn)
        logger.debug(user.encryptedPassword)
        logger.debug(ldapAuthConnectionUser)
        # logger.debug(ldapAuthConnectionPassword)
        logger.debug(ldapAuthURL)
        logger.debug(ldapAuthConnectTimeout)
        logger.debug(ldapAuthReceiveTimeout)
        logger.debug(ldapAuthUseTLS)
        logger.debug(ldapAuthTLSVersion)

        # Open LDAP Connection
        try:
            c = test_connection(
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
            raise ldap_exceptions.CouldNotOpenConnection

        result = c.result
        c.unbind()

        result['user_used'] = username
        result['user_dn_used'] = user_dn
        logger.debug("Test Connection Endpoint Result: ")
        logger.debug(result)
        return result

    @transaction.atomic
    def delete_setting(self, itemKey, data, forceDelete=False):
        try:
            querySet = Setting.objects.filter(id = itemKey)
        except:
            code = "GET_OBJECT_QUERYSET_ERROR"
            return code

        # If the value is empty and there's an override, then delete from DB
        if querySet.count() > 0:
            logger.info("Deleting setting override: " + itemKey)
            try:
                settingObject = querySet.get(id = itemKey)
                settingObject.delete_permanently()
            except Exception as e:
                print("Couldn't delete setting: " + itemKey)
                print(data)
                print(e)
                code = "DELETE_TRANSACTION_ERROR"
                return code

    @transaction.atomic
    def update_or_create_setting(self, itemKey, data, forceDelete=False):
        # if itemKey == 'LDAP_AUTH_CONNECT_TIMEOUT':
        # print(self)
        # print(itemKey)
        # print(data)

        if data['type'] == 'checkbox' or data['type'] == 'bool':
            data['type'] = 'boolean'
        if data['type'] == 'array':
            data['type'] = 'list'
        if data['type'] == 'select':
            data['type'] = 'string'

        try:
            querySet = Setting.objects.filter(id = itemKey)
        except:
            code = "GET_OBJECT_QUERYSET_ERROR"
            return code

        # If override value does not exist in DB create it
        if querySet.exclude(deleted=True).count() == 0:
            logger.info("Creating setting override: " + itemKey)
            try:
                Setting.objects.create(id = itemKey, **data)
                settingObject = querySet.get(id = itemKey)
                settingObject.deleted = False
                settingObject.save()
            except Exception as e:
                print("Couldn't save setting: " + itemKey)
                print(data)
                print(e)
                code = "CREATE_TRANSACTION_ERROR"
                return code
        # If override value exists in DB, update it
        else:
            logger.info("Updating setting override: " + itemKey)
            try:
                Setting.objects.update(id = itemKey, **data)
                settingObject = querySet.get(id = itemKey)
                settingObject.deleted = False
                settingObject.save()
            except Exception as e:
                print("Couldn't save setting: " + itemKey)
                print(data)
                print(e)
                code = "UPDATE_TRANSACTION_ERROR"
                return code

    pass