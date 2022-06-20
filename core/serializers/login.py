# from django.db.models.query import QuerySet
# from core.serializers.base import BaseSerializer
from action_serializer import serializers
# from rest_framework.validators import UniqueValidator, UniqueTogetherValidator

# from core.models import Customer, CustomerSource, PersonSex, MaritalStatus, DocumentType
# from core.utils.datetime import date_str_to_date

# USED IN: {{BASE_URL}}/api/v1.1/login/authenticate/
class LoginAuthenticateSerializer(serializers.Serializer):

    User = serializers.CharField(required=True)
    Password = serializers.CharField(required=True)