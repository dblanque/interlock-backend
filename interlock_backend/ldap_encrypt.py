from cryptography.fernet import Fernet
from interlock_backend.settings import FERNET_KEY

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