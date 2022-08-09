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
    stringToDecrypt = bytes(stringToDecrypt, encoding='utf-8')
    fernet = Fernet(key)

    decMessage = fernet.decrypt(stringToDecrypt).decode()
    return decMessage

def validateUser(request, requireAdmin=True):
    user = request.user
    if requireAdmin == True or requireAdmin is None:
        # Check user is_staff for any user that is not local default admin
        if user.username != 'admin' and (user.is_superuser == False or not user):
            raise PermissionDenied
    elif user.is_staff != True:
        raise PermissionDenied
    # Check if Local Default Super-admin is deleted/disabled
    elif user.deleted == True:
        raise PermissionDenied
    return True