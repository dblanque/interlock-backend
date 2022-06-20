from decimal import Decimal

def isfloat(x):
            try:
                a = float(x)
            except (TypeError, ValueError):
                return False
            else:
                return True

def isint(x):
    try:
        a = float(x)
        b = int(a)
    except (TypeError, ValueError):
        return False
    else:
        return a == b
    
def int_or_float_from_string(x : str):
    """ 
    Takes an x : string parameter and, if it can be converted to int or float,
    returns the corresponding type, and a boolean asserting wether x was modified or not.
    "1.5" -> float(1.5)
    "3" -> int(3)
    "1.0" -> int(1) 
    """
    if isint(x):
        #We convert to float and then round in order to allow for
        #1.0 cases
        return round(float(x)), True
    elif isfloat(x):
        return float(x), True
    else:
        return x, False