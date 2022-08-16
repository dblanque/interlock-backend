from rest_framework.exceptions import APIException

class BaseException(APIException):

    def __init__(self, data=None):
        super().__init__()
        if data is not None:
            self.setDetail(data)

    def setDetail(self, data):
        self.detail = data
        if isinstance(self.detail, dict):
            if 'code' not in self.detail:
                self.detail['code'] = self.default_code