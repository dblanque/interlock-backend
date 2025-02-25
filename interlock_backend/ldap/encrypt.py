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
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
from interlock_backend.settings import FERNET_KEY, BASE_DIR, SECRET_KEY
################################################################################

logger = logging.getLogger()
KEY_PATH = os.path.join(BASE_DIR, "private")
RSA_KEY_BITS = 8192
AES_KEY_BYTES = 32 # 256-bit key for AES-256
RSA_FILE_NAME = f"rsa_key_{str(RSA_KEY_BITS)}"
RSA_KEY_PRIV = os.path.join(KEY_PATH, f"{RSA_FILE_NAME}")
AES_FILE_NAME = f"aes_key_{str(AES_KEY_BYTES)}"
AES_KEY_PRIV = os.path.join(KEY_PATH, f"{AES_FILE_NAME}")

# KNOWLEDGE SOURCE: geeksforgeeks.org | Thank you guys!
key = FERNET_KEY

def create_rsa_key() -> RSA.RsaKey:
    key = RSA.generate(RSA_KEY_BITS)
    with open(RSA_KEY_PRIV, "wb") as key_file:
        key_file.write(key.export_key(passphrase=SECRET_KEY))
    return key

def import_rsa_key() -> RSA.RsaKey | None:
    if not os.path.isfile(RSA_KEY_PRIV):
        return None
    with open(RSA_KEY_PRIV, "rb") as key_file:
        return RSA.import_key(key_file.read(), passphrase=SECRET_KEY)

def import_or_create_rsa_key() -> RSA.RsaKey:
    rsa_key = import_rsa_key()
    if not rsa_key:
        logger.info("Generating new RSA key.")
        rsa_key = create_rsa_key()
    return rsa_key

def aes_encrypt(data: str) -> tuple[bytes]:
    """
    :rtype: tuple[bytes]
    :return: encrypted_aes_key, ciphertext, nonce, tag
	"""
    # Generate a new AES key and nonce for THIS encryption
    aes_key = get_random_bytes(32)  # AES-256
    nonce = get_random_bytes(16)    # Unique per encryption

    # Encrypt the data with AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode())

    # Encrypt the AES key with RSA
    rsa_key = import_or_create_rsa_key()
    cipher_rsa = PKCS1_OAEP.new(rsa_key.public_key())
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Return ALL components needed for decryption
    return encrypted_aes_key, ciphertext, nonce, tag

def aes_decrypt(encrypted_aes_key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> str:
    # Decrypt the AES key with RSA
    rsa_key = import_or_create_rsa_key()
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Decrypt the data with AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_data.decode()

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
