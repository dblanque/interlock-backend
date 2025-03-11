# myapp/apps.py
from django.apps import AppConfig

class CoreConfig(AppConfig):
    name = "core"

    def ready(self):
        print("Core is ready.")
        pass
