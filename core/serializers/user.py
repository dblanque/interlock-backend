import re

FIELD_VALIDATORS = {
        "username":         "ldap_user",    # username
        "password":             None,       # password
        "mail":                 None,       # email
        "givenName":            None,       # first_name
        "sn":                   None,       # last_name
        "initials":             None,       # initials
        "telephoneNumber":      None,       # phone_number
        "wWWHomePage":          None,       # webpage
        "streetAddress":        None,       # street_address
        "postalCode":           None,       # postal_code
        "l":                    None,       # town
        "st":                   None,       # state_province
        "co":                   None        # country
}

ldap_user_pattern = ".*[\]\[\"\:\;\|\=\+\*\?\<\>\/\\\,]"

def ldap_user_validator(value):
    containsInvalidChars = lambda s: re.match(ldap_user_pattern, s) != None
    return not containsInvalidChars(value)