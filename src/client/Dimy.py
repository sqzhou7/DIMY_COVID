from http import client, server
from socket import *
from binascii import hexlify, unhexlify
from socketserver import UDPServer
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import Shamir
from ecdsa import ECDH, SECP128r1
from threading import Thread
import hashlib
import time
import sys
import os
import random


BROADCAST_PORT = 56000

def EphID_gen():
    return get_random_bytes(16)





def DH_process():
    ecdh = ECDH(curve=SECP128r1)
    ecdh.generate_private_key()
    local_public_key = ecdh.get_public_key()
    

   

"""
    Seperate thread to listen to incoming broadcast
"""
class Message_Listener(Thread):
    def __init__(self) -> None:
        super().__init__()
        # create a UDP client socket for listening
        self.UDP_client = socket(AF_INET, SOCK_DGRAM)
        self.UDP_client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        #self.UDP_client.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        self.port = 56000
        self.UDP_client.bind(("", self.port))
        self.alive = True
        print("===== Message Listener up and running on")
        #print(self.UDP_client.getsockname())
        

    def run(self):
        while (self.alive):
            data, addr = self.UDP_client.recvfrom(1024)
            
            
            # message decomposition
            content_bytes = data[5:21]
            sender_identity_bytes = data[:5]
            digest = data[21:]
            
            sender_identity_str = sender_identity_bytes.decode()
            
            print("=============\nnew message received with\ncontent byte: %s\nsender_identity_str: %s\ndigest: %s\n=========" %(hexlify(content_bytes), sender_identity_str, hexlify(digest)))
        
#            print(sender_identity_str)

            # check if this broadcast is from self
            if sender_identity_str == identity_str:
                print("self broadcast")
                continue
            
            print("share received")
            # search for this port 
            result = EphID_shares.get(sender_identity_str)
            if result != None:    
                # the queue is full
                if len(result) == 3:
                    # remove the oldest record
                    result.pop(0)
                # insert just-received record
                result.append(content_bytes)

                # if the queue is full, try to reconstruct the EphID
                if len(result) == 3:
                    print("queue full")
                    shares = []
                    for x in range(3):
                        print("share #%d: %s" %(x+1, hexlify(result[x])))
                        shares.append((x+1, result[x]))
                    EphID_recon = Shamir.combine(shares)
                    
                    # check digest
                    EphID_recon_digest = hashlib.sha256(EphID_recon)
                    print("EphID reconstructed digest: %s" %hexlify(EphID_recon_digest.digest()))
                    if EphID_recon_digest.digest() == digest:
                        print("<EphID reconstructed: %s>" %hexlify(EphID_recon))

                        # EphID is the public key from sender's ECDH, therefore can use it to obtain a shared secret


            else:
                # no entry for this port yet, create a new entry and insert this share
                new_entry = []
                new_entry.append(content_bytes)
                EphID_shares.update({sender_identity_str: new_entry})
            

            print(addr)
            
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
        
        self.ecdh_instance = ECDH(curve=SECP128r1)
        self.UDP_server.settimeout(0.2)
        #self.UDP_server.bind(("127.0.0.255", self.port))
        self.alive = True
        print("===== Broadcaster up and running ======")

    def run(self):
        # generate new EphID every 15 seconds
        n = 0
        while (n < 3):
            self.EphID = get_random_bytes(16)

            # generate hash digest of the EphID
            EphID_digest = hashlib.sha256(self.EphID)


            print("EphID generated: %s, digest: %s" % (self.EphID, EphID_digest.digest()))
            shares = Shamir.split(3, 5, self.EphID)
            for idx, share in shares:
                # broadcast a share every 3 seconds
                # the share has a 50% chance to get dropped
                rand_val = random.randrange(0,2)
                print(rand_val)
                #if rand_val == 1: 
                print("Index #%d: %s broadcasted" % (idx, hexlify(share)))
                self.UDP_server.sendto(identity_bytes + share + EphID_digest.digest(), ('<broadcast>', BROADCAST_PORT))
                #else:
                 #   print("EphID share dropped")
                time.sleep(3)
            n += 1
    
    def get_broadcast_port(self):
        return self.broadcast_port



# Server would be running on the same host as Client
if len(sys.argv) != 1:
    print("\n===== Error usage, python3 Dimy.py SERVER_IP SERVER_PORT ======\n")
    exit(0)
#serverHost = sys.argv[1]
#serverPort = int(sys.argv[2])
serverAddress = ("127.0.0.1", 55000)


"""
    Main thread will be the communication with server via TCP
"""

# create a TCP socket for the communication with server
client_TCP_socket = socket(AF_INET, SOCK_STREAM)

# build connection with the server
client_TCP_socket.connect(serverAddress)

identity_port = client_TCP_socket.getsockname()[1]
identity_str = str(identity_port)
identity_bytes = identity_str.encode()

print("<identity_str: " + identity_str + ">")
print("------------connected to the server---------------")

# Generate a 16-Byte Ephemeral ID
# create an ECDH instance

#EphID = EphID_gen()
#print(EphID)
#EphID_broadcast()
#UDP_listen()

# book keeping of EphID shares from different ports on localhost using disctionary of queue(list)



client_broadcaster = EphID_Broadcast()
EphID_shares = {}

client_listener = Message_Listener()

client_broadcaster.start()
client_listener.start()

#broadcast_port = client_broadcaster.get_broadcast_port()
#print(broadcast_port)
