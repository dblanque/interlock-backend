################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.accountTypes

#---------------------------------- IMPORTS -----------------------------------#
from cryptography.fernet import Fernet
from interlock_backend.settings import FERNET_KEY
################################################################################

# KNOWLEDGE SOURCE: geeksforgeeks.org | Thank you guys!
key = FERNET_KEY

def encrypt(stringToEncrypt):
	fernet = Fernet(key)

	# Use the Fernet class instance
	# To encrypt the string string must
	# be encoded to byte string before encryption
	encMessage = fernet.encrypt(stringToEncrypt.encode())
	encMessage = str(encMessage).lstrip("b'").rstrip("'")
	return encMessage

def decrypt(stringToDecrypt):
	stringToDecrypt = bytes(stringToDecrypt, encoding='utf-8')
	fernet = Fernet(key)

	decMessage = fernet.decrypt(stringToDecrypt).decode()
	return decMessage
