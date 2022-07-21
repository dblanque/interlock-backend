from cryptography.fernet import Fernet
from interlock_backend.settings import FERNET_KEY
from django.core.exceptions import PermissionDenied

# KNOWLEDGE SOURCE: geeksforgeeks.org | Thank you guys!
key = FERNET_KEY

def encrypt(stringToEncrypt):
    fernet = Fernet(key)

    # Use the Fernet class instance
    # To encrypt the string string must
    # be encoded to byte string before encryption
    encMessage = fernet.encrypt(stringToEncrypt.encode())
    return encMessage
    
def decrypt(stringToDecrypt):
    fernet = Fernet(key)

    decMessage = fernet.decrypt(stringToDecrypt).decode()
    return decMessage

def validateUser(request, requestUser):
    user = requestUser
    # If user is not Local Default Super-admin
    if user.username != 'admin':
        if not request.data['encPwd']:
            raise PermissionDenied
        requestPwd = request.data.pop('encPwd')
        requestPwd = "b'" + requestPwd + "'"
        # Check user is_staff for any user that is not local default admin
        if (user.is_staff == False or not user) or (user.encryptedPassword != requestPwd):
            raise PermissionDenied
    # Check if Local Default Super-admin is deleted/disabled
    elif user.deleted == True:
        raise PermissionDenied
    return True