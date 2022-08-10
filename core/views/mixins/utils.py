################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.utils
# Contains extra utilities and functions

#---------------------------------- IMPORTS -----------------------------------#
import socket

def testPort(ip , port, timeout=5):
  s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
  s.settimeout(timeout)
  try:
    s.connect((ip , int(port)))
    s.settimeout(None)
    s.shutdown(2)
    return True
  except:
    return False

def recursiveFindInDict(obj, key):
  if key in obj: return obj[key]
  for k, v in obj.items():
      if isinstance(v,dict):
          item = recursiveFindInDict(v, key)
          if item is not None:
              return item
# Check if in current level array
# check if has children
# if has children check in children array
# if children have children call itself

def __getCN__(dn):
  return str(dn).split(',')[0].split('=')[-1]

def __getRelativeDN__(dn):
  return str(dn).split(',').pop(0).join(',')

def testFunc(*args):
  for i in args:
    print(i)
