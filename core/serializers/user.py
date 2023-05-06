import re

ldap_user_pattern = ".*[\]\[\"\:\;\|\=\+\*\?\<\>\/\\\,]"

def ldap_user_validator(value):
    containsInvalidChars = lambda s: re.match(ldap_user_pattern, s) != None
    return not containsInvalidChars(value)