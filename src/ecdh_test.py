from ctypes import sizeof
from ecdsa import ECDH, SECP128r1

import sys

server_ecdh = ECDH(curve=SECP128r1)

server_ecdh.generate_private_key()

server_public_key = server_ecdh.get_public_key()

server_public_key_bytes = server_public_key.to_string("compressed")



print(server_public_key_bytes.hex())
print(server_public_key_bytes[1:].hex())

server_public_key_shamir = server_public_key_bytes[1:]
server_public_key_header = server_public_key_bytes[0:1]

server_public_key_re = server_public_key_header + server_public_key_shamir


print(server_public_key_re.hex())


print("second round")

server_ecdh.generate_private_key()

server_public_key = server_ecdh.get_public_key()

server_public_key_bytes = server_public_key.to_string("compressed")

print(server_public_key_bytes.hex())