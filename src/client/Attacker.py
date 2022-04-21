from http import client, server
from socket import *
from binascii import hexlify, unhexlify
from socketserver import UDPServer
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import Shamir
from ecdsa import ECDH, SECP128r1
from threading import Thread
from bitarray import bitarray
import hashlib
import time
import sys
import os
import random

import threading

BROADCAST_PORT = 56000
SERVER_PORT = 55000

class Message_Listener(Thread):
            
    def __init__(self) -> None:
        super().__init__()
        # create a UDP client socket for listening
        self.UDP_client = socket(AF_INET, SOCK_DGRAM)
        self.UDP_client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        #self.UDP_client.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        self.UDP_client.bind(("", BROADCAST_PORT))
        self.alive = True
        # self.all_DBF = []
        print("===== Attacker Listener up and running on")
        #print(self.UDP_client.getsockname())

    def run(self):
        global sender_identity_bytes_collection
        while (self.alive):
            data, addr = self.UDP_client.recvfrom(1024)
            # message decomposition
            for i in range(1, len(data)+1):
                if data[i-1:i] == b' ':
                    length = i
                    break

            # try to get other nodes' identities and use those identities to broadcast
            sender_identity_bytes = data[:length-1]
            threadlock.acquire()
            sender_identity_bytes_collection.add(sender_identity_bytes)
            threadlock.release()
            
            
                
            
          
"""
    Seperate thread to broadcast EphID shares
"""
class EphID_Broadcast(Thread):
    def __init__(self) -> None:
        super().__init__()
        # create a UDP server socket for broadcasting
        self.UDP_server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        self.UDP_server.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        #self.broadcast_port = self.UDP_server.getsockname()[1]
        #print(self.UDP_server.getsockname())
        # use the last 16 bits as the Shamir key to generate shares
        self.UDP_server.settimeout(0.2)
        #self.UDP_server.bind(("127.0.0.255", self.port))
        self.alive = True
        print("===== Attacker broadcaster up and running ======")

    def run(self):
        # generate new EphID every 5s
        while True:
            ecdh_instance.generate_private_key()
            public_key = ecdh_instance.get_public_key()   # generate key instance

            # EphID
            public_key_bytes = public_key.to_string("compressed") # generate byte string for the public key

            # generate hash digest of the EphID
            EphID_digest = hashlib.sha256(public_key_bytes)
            # print("BROADCASTERER >>> EphID generated: %s, digest: %s" % (public_key_bytes.hex(), EphID_digest.digest().hex()))
            shares = Shamir.split(3, 5, public_key_bytes[1:])
            for idx, share in shares:
                
                
                # wait for the first sender
                threadlock.acquire()
                while len(sender_identity_bytes_collection) == 0:
                    time.sleep(1)

                for sender_id in sender_identity_bytes_collection:
                    self.UDP_server.sendto(sender_id + b' ' + public_key_bytes[0:1] + idx.to_bytes(1, 'big') + share + EphID_digest.digest(), ('<broadcast>', BROADCAST_PORT))

                threadlock.release()
                time.sleep(1)

    
    def get_broadcast_port(self):
        return self.broadcast_port



# Server would be running on the same host as Client
if len(sys.argv) != 1:
    print("\n===== Error usage, python3 Dimy.py SERVER_IP SERVER_PORT ======\n")
    exit(0)
#serverHost = sys.argv[1]
#serverPort = int(sys.argv[2])
serverAddress = ("127.0.0.1", SERVER_PORT)


"""
    Main thread will be the communication with server via TCP
"""

# create a TCP socket for the communication with server
# client_TCP_socket = socket(AF_INET, SOCK_STREAM)

# # build connection with the server
# client_TCP_socket.connect(serverAddress)

# identity_port = client_TCP_socket.getsockname()[1]
# identity_str = str(identity_port)
# identity_bytes = identity_str.encode()

# # holding the identity bytes from all other nodes
sender_identity_bytes_collection = set()


# print("<identity_str: " + identity_str + ">")
# print("------------connected to the server---------------")

# create an ECDH instance
ecdh_instance = ECDH(curve=SECP128r1)

# Thread synchronization
threadlock=threading.Lock()

# book keeping of EphID shares from different ports on localhost using disctionary of queue(list)


EphID_shares = {}
client_broadcaster = EphID_Broadcast()
client_listener = Message_Listener()

client_broadcaster.start()
client_listener.start()

#broadcast_port = client_broadcaster.get_broadcast_port()
#print(broadcast_port)
