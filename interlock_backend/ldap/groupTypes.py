LDAP_GROUP_TYPES = {
    "GROUP_DISTRIBUTION": {
        "value" : 0,
        "val_bin" : str(bin(0))[2:].zfill(32),
        "index": str(bin(0))[2:].zfill(32).find("1")
    },
    "GROUP_SYSTEM": {
        "value" : 1,
        "val_bin" : str(bin(1))[2:].zfill(32),
        "index": str(bin(1))[2:].zfill(32).find("1")
    },
    "GROUP_GLOBAL": {
        "value" : 2,
        "val_bin" : str(bin(2))[2:].zfill(32),
        "index": str(bin(2))[2:].zfill(32).find("1")
    },
    "GROUP_DOMAIN_LOCAL": {
        "value" : 4,
        "val_bin" : str(bin(4))[2:].zfill(32),
        "index": str(bin(4))[2:].zfill(32).find("1")
    },
    "GROUP_UNIVERSAL": {
        "value" : 8,
        "val_bin" : str(bin(8))[2:].zfill(32),
        "index": str(bin(8))[2:].zfill(32).find("1")
    },
    "GROUP_SECURITY": {
        "value" : 2147483648,
        "val_bin" : str(bin(2147483648))[2:].zfill(32),
        "index": str(bin(2147483648))[2:].zfill(32).find("1")
    }
}