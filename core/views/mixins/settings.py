from django.conf import Settings
from rest_framework import viewsets
from core.models.settings import Setting
from django.db import transaction

class SettingsViewMixin(viewsets.ViewSetMixin):

    def update_or_create_setting(self, itemKey, data):
        if itemKey == 'LDAP_AUTH_CONNECT_TIMEOUT':
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