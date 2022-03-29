from socket import *
from threading import Thread
import sys, select


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





if __name__ == "main":
    print("yes")