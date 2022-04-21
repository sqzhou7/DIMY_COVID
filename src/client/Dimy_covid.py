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
import mmh3
import threading

BROADCAST_PORT = 56000
SERVER_PORT = 55000

def EphID_gen():
    return get_random_bytes(16)





def DH_process():
    ecdh = ECDH(curve=SECP128r1)
    ecdh.generate_private_key()
    local_public_key = ecdh.get_public_key()
    

# create a BloomFilter class
class BloomFilter():
    def __init__(self, size, num_of_hash):
        super(BloomFilter, self).__init__()
        #create fixed size bitarray
        self.bf = bitarray(size)
        self.bf.setall(0)
        self.size = size
        self.hash_num = num_of_hash
        self.store_num = 0
        
    def __len__(self):
        return self.size
 
    
    def add(self, key):
        #use several hashes
        for seed in range(self.hash_num):
            index = mmh3.hash(key, seed) % self.size
            self.bf[index] = 1
        self.store_num +=1
 
    def __contains__(self, key):
        #check whether it is in the bloomfilter
        result = True
        for seed in range(self.hash_num):
            index = mmh3.hash(key, seed) % self.size
            if self.bf[index] == 0:
                result = False
        return result
    # copy itself
    def copy(self):
        cp = BloomFilter(self.size, self.hash_num)
        cp.bf = self.bf.copy()
        cp.size = self.size
        cp.hash_num = self.hash_num
        cp.store_num = self.store_num
        return cp
    # reset itself
    def clear(self):
        self.bf.setall(0)
        self.store_num = 0
    # check whether it has any data  
    def isNull(self):
        if self.bf.count(1) == 0:
            return True
        return False
        

"""
    Seperate thread to listen to incoming broadcast
"""
DBF = BloomFilter(100000, 3)
DBF_all = []
COVID = False
# wait 10s, store the DBF and reset DBF(the time set is convenient to test, we can set 90s)
class Store_DBF(Thread):
    def run(self):
        global DBF, DBF_all
        while True:
            time.sleep(90)
            threadlock.acquire()
            if not DBF.isNull():
                if len(DBF_all) == 6:
                    DBF_all.pop(0)
                    DBF_all.append(DBF.copy())
                else:
                    DBF_all.append(DBF.copy())
                print("LISTENER >>> the number of stored DBF: %d"%(len(DBF_all)))
                DBF.clear()
                print("LISTENER >>> 90s, a new DBF gets created")
            threadlock.release()

# wait 60s, encode all DBF into a QBF and send QBF to server(the time set is convenient to test, we can set 540s) 
class Send_QBF(Thread):
    def run(self):
        global DBF, DBF_all, COVID
        while True:
            time.sleep(540)
            QBF = BloomFilter(100000, 3)
            threadlock.acquire()
            # if the client is diagnosed with COVID-19, stop sending QBF
            if (len(DBF_all) != 0) and (not COVID):
                for d in DBF_all:
                    QBF.add(d.bf.to01())
                print("LISTENER >>> combine all the available DBFs into a single QBF")
                client_TCP_socket.sendall(('Q'+QBF.bf.to01()).encode())
                print("LISTENER >>> send QBF to the back-end server")
                server_send = client_TCP_socket.recv(1024)
                message = server_send.decode()
                # If the result is 'matched', we set COVID True
                if message == "Matched":
                    COVID = True
                threadlock.release()
                print("LISTENER >>> Result: ", message)
            else:
                threadlock.release()
# For this client, the event will not happen
class Event(Thread):
    def run(self):
        global COVID
        time.sleep(500)
        threadlock.acquire()
        COVID = True
        threadlock.release()

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
        print("===== Message Listener up and running on")
        #print(self.UDP_client.getsockname())

    def run(self):
        global DBF, COVID, DBF_all
        storeDBF = Store_DBF()
        storeDBF.start()
        sendQBF = Send_QBF()
        sendQBF.start()
        e = Event()
        e.start()
        idx_collect = set()
        while (self.alive):
            data, addr = self.UDP_client.recvfrom(1024)
            # message decomposition
            for i in range(1, len(data)+1):
                if data[i-1:i] == b' ':
                    length = i
                    break
            sender_identity_bytes = data[:length-1]
            header_byte = data[length:length+1]
            content_bytes = data[length+1:length+18]
            digest = data[length+18:]
            sender_identity_str = sender_identity_bytes.decode()
            # check if this broadcast is from self
            if sender_identity_str == identity_str:
                # print("LISTENER >>> self broadcast")
                continue
            # print("LISTENER >>> share received from", addr, "\n=========\nnew message received with\ncontent byte: %s\nsender_identity_str: %s\nheader_byte: %s\ndigest: %s\n=========" %(hexlify(content_bytes), sender_identity_str, hexlify(header_byte), hexlify(digest)))
            print("LISTENER >>> share received from ", addr)
            # search for this port 
            result = EphID_shares.get(sender_identity_str)
            if result != None:    
                # the queue is full
                print("LISTENER >>> number of shares for %s: %d"%(sender_identity_str,len(result)))
                if len(result) == 3:
                    # remove the oldest record
                    result.pop(0)
                # insert just-received record
                for i in range(len(result)):
                    index = int.from_bytes(result[i][0:1], 'big')
                    idx_collect.add(index)
                if int.from_bytes(content_bytes[0:1], 'big') in idx_collect:
                    idx_collect.clear()
                    continue
                idx_collect.clear()
                result.append(content_bytes)
                # if the queue is full, try to reconstruct the EphID
                if len(result) == 3:
                    # print("LISTENER >>> queue full")
                    shares = []
                    for x in range(3):
                        index = int.from_bytes(result[x][0:1], 'big')
                        print("LISTENER >>> share #%d: %s" %(index, hexlify(result[x][1:])))
                        shares.append((index, result[x][1:]))
                    EphID_recon = header_byte + Shamir.combine(shares)
                    print("LISTENER >>> EphID reconstructed: %s" %hexlify(EphID_recon))
                    # check digest
                    EphID_recon_digest = hashlib.sha256(EphID_recon)
                    print("LISTENER >>> EphID reconstructed digest: %s" %hexlify(EphID_recon_digest.digest()))
                    if EphID_recon_digest.digest() == digest:
                        print("LISTENER >>> EphID matched")
                        # EphID is the public key from sender's ECDH, therefore can use it to obtain a shared secret
                        ecdh_instance.load_received_public_key_bytes(EphID_recon)
                        new_EncID = ecdh_instance.generate_sharedsecret_bytes()
                        print("LISTENER >>> new encID generated by Diffie-Hellman: %s" %new_EncID.hex())

                        ######### Bloom filter starts here
                        threadlock.acquire()
                        # add new_EncID into DBF
                        DBF.add(new_EncID)
                        print("LISTENER >>> Encoding an EncID into the same DBF and deleting the EncID. The number of EncID in current DBF: %d"%DBF.store_num)
                        # If thhis client is diagnosed with COVID-19, send a CBF and stop the while loop
                        if COVID:
                            CBF = BloomFilter(100000, 3)
                            for d in DBF_all:
                                CBF.add(d.bf.to01())
                            threadlock.release()
                            print("LISTENER >>> combine all the available DBFs into a single CBF")
                            client_TCP_socket.sendall(('C'+CBF.bf.to01()).encode())
                            print("LISTENER >>> send CBF to the back-end server")
                            break
                        else:
                            threadlock.release()
            else:
                # no entry for this port yet, create a new entry and insert this share
                new_entry = []
                new_entry.append(content_bytes)
                EphID_shares.update({sender_identity_str: new_entry})
                
            
          
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
        print("===== Broadcaster up and running ======")

    def run(self):
        # generate new EphID every 15 seconds
        n = 0
        # n is set for testing purpose
        while True:
            ecdh_instance.generate_private_key()
            public_key = ecdh_instance.get_public_key()   # generate key instance

            # EphID
            public_key_bytes = public_key.to_string("compressed") # generate byte string for the public key

            # generate hash digest of the EphID
            EphID_digest = hashlib.sha256(public_key_bytes)
            print("BROADCASTERER >>> EphID generated: %s, digest: %s" % (public_key_bytes.hex(), EphID_digest.digest().hex()))
            shares = Shamir.split(3, 5, public_key_bytes[1:])
            for idx, share in shares:
                # broadcast a share every 3 seconds
                # the share has a 50% chance to get dropped
                rand_val = random.random()
                # print(rand_val)
                if rand_val >= 0.2: 
                    print("BROADCASTERER >>> Index #%d: %s broadcasted" % (idx, hexlify(share)))
                    self.UDP_server.sendto(identity_bytes + b' ' + public_key_bytes[0:1] + idx.to_bytes(1, 'big') + share + EphID_digest.digest(), ('<broadcast>', BROADCAST_PORT))
                else:
                    print("BROADCASTERER >>> EphID share dropped")
                time.sleep(3)

    
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
client_TCP_socket = socket(AF_INET, SOCK_STREAM)

# build connection with the server
client_TCP_socket.connect(serverAddress)

identity_port = client_TCP_socket.getsockname()[1]
identity_str = str(identity_port)
identity_bytes = identity_str.encode()



print("<identity_str: " + identity_str + ">")
print("------------connected to the server---------------")

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
