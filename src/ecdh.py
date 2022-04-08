from ctypes import sizeof
from ecdsa import ECDH, SECP128r1
import sys

server_ecdh = ECDH(curve=SECP128r1)
peer_ecdh = ECDH(curve=SECP128r1)
server_ecdh.generate_private_key()
peer_ecdh.generate_private_key()

server_public_key = server_ecdh.get_public_key()
#print(server_public_key.to_string("uncompressed").hex())
peer_public_key = peer_ecdh.get_public_key()
#print(peer_public_key.to_string("uncompressed").hex())

server_public_key_bytes = server_public_key.to_string("compressed")
peer_public_key_bytes = peer_public_key.to_string("compressed")
print(len(server_public_key_bytes))
print(server_public_key_bytes.hex())
print(peer_public_key_bytes.hex())
print("compressed: {0}".format(server_public_key_bytes.hex()))
print("compressed: {0}".format(peer_public_key_bytes.hex()))

server_ecdh.load_received_public_key_bytes(peer_public_key_bytes)
server_secret = server_ecdh.generate_sharedsecret_bytes()
print(server_secret)


peer_ecdh.load_received_public_key_bytes(server_public_key_bytes)
peer_secret = peer_ecdh.generate_sharedsecret_bytes()


print(peer_secret)