from multiprocessing.connection import wait
from socket import *
from threading import Thread
import sys, select
import time
from bitarray import bitarray



# acquire server host and port from command line parameter
if len(sys.argv) != 3:
    print("\n===== Usage: python3 DimyServer.py SERVER_ADDRESS SERVER_PORT ======\n")
    exit(0)
serverHost = sys.argv[1]
serverPort = int(sys.argv[2])
serverAddress = (serverHost, serverPort)

# define socket for the server side and bind address
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(serverAddress)


CBF_all =[]
class ClientThread(Thread):
    def __init__(self, clientAddress, clientSocket):
        Thread.__init__(self)
        self.clientAddress = clientAddress
        self.clientSocket = clientSocket
        self.clientAlive = False
        
        print("===== New connection created for: ", clientAddress)
        self.clientAlive = True
        
    def run(self):
        message = ''
        global CBF_all
        while self.clientAlive:
            # use recv() to receive message from the client
            data = self.clientSocket.recv(102400)
            message = data.decode()
            
            if message[0] =='C':
                CBF = bitarray(message[1:])
                CBF_all.append(CBF.copy())
                print("Server >>> Accept a CBF")
            if message[0] == 'Q':
                QBF = bitarray(message[1:])
                print("Server >>> Accept a QBF")
                print("Server >>> Matching QBF and CBF")
                count_match = 0
                if len(CBF_all) !=0:
                    for c in CBF_all:
                        matchResult = QBF & c
                        num_sameBits = matchResult.count(1)
                        if num_sameBits >= 3:
                            count_match += 1
                    if count_match >0:
                        print("Server >>> Result: Matched")
                        self.clientSocket.send("Matched".encode())
                    else:
                        print("Server >>> Result: Not matched")
                        self.clientSocket.send("Not matched".encode())
                else:
                    print("Server >>> Result: no CBF, Not matched")
                    self.clientSocket.send("Not matched".encode())


print("\n===== Server is running =====")
print("===== Waiting for connection request from clients...=====")


while True:
    serverSocket.listen()
    clientSockt, clientAddress = serverSocket.accept()
    clientThread = ClientThread(clientAddress, clientSockt)
    clientThread.start()
