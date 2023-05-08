from rest_framework.exceptions import APIException

class BaseException(APIException):
    def __init__(self, data=None):
        super().__init__()
        if data is not None:
            self.setDetail(data)
        else:
            self.detail = {
                "code": self.default_code,
                "detail": self.default_detail
            }

    def setDetail(self, data):
        self.detail = data
        if isinstance(self.detail, dict):
            if 'code' not in self.detail:
                self.detail['code'] = self.default_code
            if 'detail' not in self.detail:
                self.detail['detail'] = self.default_detail

class MissingDataKey(BaseException):
    status_code = 500
    default_detail = 'Missing key in data'
    default_code = 'data_key_missing'