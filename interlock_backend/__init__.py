from django.apps import AppConfig

class InterlockConfig(AppConfig):
    name = 'interlock_backend'
    verbose_name = "Interlock Backend"
    def ready(self):
        pass # startup code here
