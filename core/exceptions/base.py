from rest_framework.exceptions import APIException

class BaseException(APIException):

    def setDetail(self, data):
        self.default_detail = data