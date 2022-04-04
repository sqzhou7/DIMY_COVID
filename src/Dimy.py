from socket import *
import sys
import os

###

'''
Generate a 16-Byte Ephemeral ID  

'''
def EphID_Gen():
    return os.urandom(16)

'''
Broadcast n shares of EphID 
'''
def broadcast():
    
    return 0




#Server would be running on the same host as Client
if len(sys.argv) != 3:
    print("\n===== Error usage, python3 Dimy.py SERVER_IP SERVER_PORT ======\n")
    exit(0)
serverHost = sys.argv[1]
serverPort = int(sys.argv[2])
serverAddress = (serverHost, serverPort)

# define a socket for the client side, it would be used to communicate with the server
clientSocket = socket(AF_INET, SOCK_STREAM)

# build connection with the server and send message to it
clientSocket.connect(serverAddress)

EphID = EphID_Gen()
print(EphID)