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