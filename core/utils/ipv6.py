import socket
from struct import unpack

# src: https://stackoverflow.com/questions/10558441/inet-aton-similar-function-for-ipv6
def ipv6_to_integer(ipv6_addr):
    ipv6_addr = socket.inet_pton(socket.AF_INET6, ipv6_addr)
    a, b = unpack(">QQ", ipv6_addr)
    return (a << 64) | b
