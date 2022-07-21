from django.conf import Settings
from rest_framework import viewsets
from core.models.settings import Setting
from django.db import transaction
from interlock_backend import ldap_settings
import copy
import logging

logger = logging.getLogger(__name__)

class SettingsViewMixin(viewsets.ViewSetMixin):

    def normalizeSaveValues(self, settingKey, settingObject):

        # Set the Type for the Front-end
        if 'type' in ldap_settings.SETTINGS_WITH_ALLOWABLE_OVERRIDE[settingKey]:
            settingObject['type'] = ldap_settings.SETTINGS_WITH_ALLOWABLE_OVERRIDE[settingKey]['type']
        else:
            settingObject['type'] = 'string'

        if settingKey == "LDAP_AUTH_URL":
            settingObject['value'] = copy.deepcopy(ldap_settings.__dict__[settingKey])
            for key, value in enumerate(settingObject['value']):
                settingObject['value'][key] = str(value)
        if settingKey == "LDAP_AUTH_TLS_VERSION":
            settingObject['value'] = copy.deepcopy(str(ldap_settings.__dict__[settingKey]).split('.')[-1])
        return settingObject

    def getSettingsList(self, settingList=ldap_settings.SETTINGS_WITH_ALLOWABLE_OVERRIDE):
        data = {}
        
        # Loop for each constant in the ldap_settings.py file
        for c in ldap_settings.__dict__:
            # If the constant is in the settingList array
            if c in settingList:
                # Init Object/Dict
                data[c] = {}
                querySet = Setting.objects.filter(id = c).exclude(deleted=True)
                # If an override exists in the DB do the following
                if querySet.count() > 0:
                    logger.debug(c + "was fetched from DB")
                    settingObject = querySet.get(id = c)
                    value = settingObject.value
                    value = settingObject.type
                    data[c]['value'] = value

                    data[c] = self.normalizeSaveValues(settingKey=c, settingObject=data[c])
                # If no override exists use the manually setup constant
                else:
                    logger.debug(c + "was fetched from Constants File")
                    data[c]['value'] = ldap_settings.__dict__[c]
                    
                    data[c] = self.normalizeSaveValues(settingKey=c, settingObject=data[c])
                    logger.debug(c)
                    logger.debug(ldap_settings.__dict__[c])
                    logger.debug(data[c])

        return data

    def resetSettings(self):
        # Deletes all setting overrides in DB
        [setting.delete_permanently() for setting in Setting.objects.all()]
        return True

    def update_or_create_setting(self, itemKey, data):
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
            code = "UPDATE_GET_OBJECT_ERROR"
            return code

        if querySet.exclude(deleted=True).count() == 0:
            try:
                Setting.objects.update_or_create(id = itemKey, **data)
                settingObject = querySet.get(id = itemKey)
                settingObject.deleted = False
                settingObject.save()
            except Exception as e:
                print("Couldn't save setting: " + itemKey)
                print(data)
                print(e)
                code = "UPDATE_TRANSACTION_ERROR"
                return code
        elif data['value'] == "" and querySet.count() > 0:
            try:
                settingObject = querySet.get(id = itemKey)
                settingObject.value(None)
                settingObject.delete(self)
            except Exception as e:
                print("Couldn't delete setting: " + itemKey)
                print(data)
                print(e)
                code = "UPDATE_TRANSACTION_ERROR"
                return code
    pass