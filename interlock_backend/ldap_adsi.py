LDAP_PERMS = {
    "LDAP_UF_SCRIPT" : str(bin(1))[2:].zfill(32),
    "LDAP_UF_ACCOUNT_DISABLE" : str(bin(2))[2:].zfill(32),
    "LDAP_UF_HOMEDIR_REQUIRED" : str(bin(8))[2:].zfill(32),
    "LDAP_UF_LOCKOUT" : str(bin(16))[2:].zfill(32),
    "LDAP_UF_PASSWD_NOTREQD" : str(bin(32))[2:].zfill(32),
    "LDAP_UF_PASSWD_CANT_CHANGE" : str(bin(64))[2:].zfill(32),
    "LDAP_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED" : str(bin(128))[2:].zfill(32),
    "LDAP_UF_NORMAL_ACCOUNT" : str(bin(512))[2:].zfill(32),
    "LDAP_UF_INTERDOMAIN_TRUST_ACCOUNT" : str(bin(2048))[2:].zfill(32),
    "LDAP_UF_WORKSTATION_TRUST_ACCOUNT" : str(bin(4096))[2:].zfill(32),
    "LDAP_UF_SERVER_TRUST_ACCOUNT" : str(bin(8192))[2:].zfill(32),
    "LDAP_UF_DONT_EXPIRE_PASSWD" : str(bin(65536))[2:].zfill(32),
    "LDAP_UF_MNS_LOGON_ACCOUNT" : str(bin(131072))[2:].zfill(32),
    "LDAP_UF_SMARTCARD_REQUIRED" : str(bin(262144))[2:].zfill(32),
    "LDAP_UF_TRUSTED_FOR_DELEGATION" : str(bin(524288))[2:].zfill(32),
    "LDAP_UF_NOT_DELEGATED" : str(bin(1048576))[2:].zfill(32),
    "LDAP_UF_USE_DES_KEY_ONLY" : str(bin(2097152))[2:].zfill(32),
    "LDAP_UF_DONT_REQUIRE_PREAUTH" : str(bin(4194304))[2:].zfill(32),
    "LDAP_UF_PASSWORD_EXPIRED" : str(bin(8388608))[2:].zfill(32),
    "LDAP_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION" : str(bin(16777216))[2:].zfill(32),
    "LDAP_UF_NO_AUTH_DATA_REQUIRED" : str(bin(33554432))[2:].zfill(32),
    "LDAP_UF_PARTIAL_SECRETS_ACCOUNT" : str(bin(67108864))[2:].zfill(32)
}

LDAP_PERM_BIN_BASE = "0"*32

def convert_to_bin(value):
    casted_int = int(str(value))
    return str(bin(casted_int))[2:].zfill(32)
    