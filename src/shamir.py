from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir

from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import Shamir


key_origin = get_random_bytes(16)
print("Original key: %s" %hexlify(key_origin))
shares = Shamir.split(2, 5, key_origin)
for idx, share in shares:
    print( "Index #%d: %s" % (idx, hexlify(share)))

shares_new = []
for x in range(2):
    #in_str = input("Enter index and share separated by comma: ")
    print((shares[x]))
    shares_new.append((shares[x]))
key = Shamir.combine(shares)
print("Reconstructed key: %s" %hexlify(key))
