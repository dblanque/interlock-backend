from rest_framework import viewsets
from core.models.settings import Setting
from core.models.user import User
from django.db import transaction
from interlock_backend.ldap.connector import open_connection
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

    def testSettings(self, user=None):
        if user == None:
            c = open_connection()
        else:
            c = open_connection(user.username)

        result = c.result
        c.unbind()
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