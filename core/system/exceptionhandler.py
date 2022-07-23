from rest_framework.views import exception_handler
from rest_framework.response import Response
from core.system.responsehandler import ResponseHandler

def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    # Now add the HTTP status code to the response.
    if response is not None:
        response.data['status_code'] = response.status_code

    print(response)

    return response

# def exception_handler(exc, context):
#     """
#     Returns the response that should be used for any given exception.
#     By default we handle the REST framework `APIException`, and also
#     Django's built-in `Http404` and `PermissionDenied` exceptions.
#     Any unhandled exceptions may return `None`, which will cause a 500 error
#     to be raised.
#     """
#     if isinstance(exc, Http404):
#         exc = exceptions.NotFound()
#     elif isinstance(exc, PermissionDenied):
#         exc = exceptions.PermissionDenied()

#     if isinstance(exc, exceptions.APIException):
#         headers = {}
#         if getattr(exc, 'auth_header', None):
#             headers['WWW-Authenticate'] = exc.auth_header
#         if getattr(exc, 'wait', None):
#             headers['Retry-After'] = '%d' % exc.wait

#         if isinstance(exc.detail, (list, dict)):
#             data = exc.detail
#         else:
#             data = {'detail': exc.detail}

#         set_rollback()
#         return Response(data, status=exc.status_code, headers=headers)

#     return None

# def custom_exception_handler(exc, context):
#     # Call REST framework's default exception handler first,
#     # to get the standard error response.
#     original_response = exception_handler(exc, context)

#     print(original_response.data.values())

#     original_response_code = next(iter(original_response.data.values()))[0].code
#     original_fields = ', '.join(original_response.data.keys())
#     code = None
#     details = None
#     # print(og_response_code)
#     # Now add the HTTP status code to the response.
#     if original_response_code == 'required':
#         code = 'MISSING_FIELD'
#         details = original_fields

#     return Response(
#         data = ResponseHandler.send(code, details)
#     )