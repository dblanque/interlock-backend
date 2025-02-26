################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.accountTypes

#---------------------------------- IMPORTS -----------------------------------#
import os
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from core.models.interlock_settings import (
	InterlockSetting,
	TYPE_BYTES,
	SETTING_KEY_AES
)
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
from time import perf_counter
from interlock_backend.settings import FERNET_KEY, BASE_DIR, SECRET_KEY, AES_RSA_PERF_LOGGING
################################################################################

logger = logging.getLogger()
KEY_PATH = os.path.join(BASE_DIR, "private")
RSA_KEY_BITS = 4096
KEY_FILE_EXPORT = os.path.join(KEY_PATH, f"rsa_{RSA_KEY_BITS}.pem")

# KNOWLEDGE SOURCE: geeksforgeeks.org | Thank you guys!
key = FERNET_KEY

def fernet_encrypt(data: str, return_bytes=False, bytes_encoding="utf-8") -> str | bytes:
	"""
	:rtype: str | bytes
	:return: bytes cast to string by default
	"""
	fernet = Fernet(key)
	encMessage = fernet.encrypt(data.encode(encoding=bytes_encoding))
	if return_bytes:
		return encMessage
	encMessage = str(encMessage).replace("b'","", 1).rstrip("'\"")
	return encMessage

def fernet_decrypt(data, bytes_encoding="utf-8") -> str:
	if isinstance(data, str):
		data = bytes(data, encoding=bytes_encoding)
	fernet = Fernet(key)

	decMessage = fernet.decrypt(data).decode()
	return decMessage

def create_rsa_key() -> RSA.RsaKey:
	key = RSA.generate(RSA_KEY_BITS)
	key_db_obj = InterlockSetting.objects.create(
		s_name=SETTING_KEY_AES,
		s_type=TYPE_BYTES,
		s_data_bytes=key.export_key(passphrase=SECRET_KEY)
	)
	key_db_obj.save()
	return key

def import_rsa_key() -> RSA.RsaKey | None:
	try:
		key = InterlockSetting.objects.get(s_name=SETTING_KEY_AES, s_type=TYPE_BYTES)
	except InterlockSetting.DoesNotExist:
		key = None
	if key:
		return RSA.import_key(key.s_data_bytes, passphrase=SECRET_KEY)
	return key

def import_or_create_rsa_key() -> RSA.RsaKey:
	rsa_key = import_rsa_key()
	if not rsa_key:
		logger.info("Generating new RSA key.")
		rsa_key = create_rsa_key()
	return rsa_key

class InterlockRsaKey():
	def __init__(self):
		self.key = import_or_create_rsa_key()

	def resync(self):
		import_or_create_rsa_key()

# We gotta use class to keep the key in memory and avoid encrypt/decrypt
# operations on the key itself all the time.
interlock_rsa = InterlockRsaKey()

def aes_encrypt(data: str, fernet_pass=False) -> tuple[bytes]:
	"""
	:param fernet_pass: Whether to do an additional Fernet-based Encryption, 
	defaults to False
	:rtype: tuple[bytes]
	:return: encrypted_aes_key, ciphertext, nonce, tag
	"""
	if AES_RSA_PERF_LOGGING:
		start = perf_counter()

	# Generate a new AES key and nonce for THIS encryption
	aes_key = get_random_bytes(32)  # AES-256
	nonce = get_random_bytes(16)    # Unique per encryption

	# Encrypt the data with AES-GCM
	cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
	if fernet_pass:
		data = fernet_encrypt(data)
	ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode())

	# Encrypt the AES key with RSA
	rsa_key = interlock_rsa.key
	cipher_rsa = PKCS1_OAEP.new(rsa_key.public_key())
	encrypted_aes_key = cipher_rsa.encrypt(aes_key)

	if AES_RSA_PERF_LOGGING:
		end = perf_counter()
		print(f"Time to encrypt: {end-start}")

	# Return ALL components needed for decryption
	return encrypted_aes_key, ciphertext, nonce, tag

def aes_decrypt(
		encrypted_aes_key: bytes,
		ciphertext: bytes,
		nonce: bytes,
		tag: bytes,
		fernet_pass=False
	) -> str:
	"""
	:param fernet_pass: Whether to do an additional Fernet-based Encryption, 
	defaults to False
	:rtype: str
	:return: Decrypted data
	"""
	if AES_RSA_PERF_LOGGING:
		start = perf_counter()

	# Decrypt the AES key with RSA
	rsa_key = interlock_rsa.key
	cipher_rsa = PKCS1_OAEP.new(rsa_key)
	aes_key = cipher_rsa.decrypt(encrypted_aes_key)

	# Decrypt the data with AES-GCM
	cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
	decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

	if AES_RSA_PERF_LOGGING:
		end = perf_counter()
		print(f"Time to decrypt: {end-start}")

	if fernet_pass is True:
		return fernet_decrypt(decrypted_data.decode())
	else:
		return decrypted_data.decode()
