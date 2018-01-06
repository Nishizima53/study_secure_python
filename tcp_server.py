# -*- coding: utf-8 -*-

import socket
import threading

bind_ip = "0.0.0.0"
bind_port = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((bind_ip,bind_port))

server.listen(5)

print "[*] Listening on %s:%d" % (bind_ip,bind_port)

# thread to handle connection from clients
def handle_client(client_socket):
    
    #display data from client
    request = client_socket.recv(1024)
    #the number in brackets is maximum bytes that we can recieve in one packet
    #request content is sent by clients send object of python

    
    print "[*] Received: %s" % request
    
    #return packet
    client_socket.send("ACK!")
    
    client_socket.close()
    
    
while True:
    
    client,addr = server.accept()
    #addr is a tuple that (ip addr, port number) 
    #? client is the socket which has some infomtion (for exam what object send to me and where locate in memory)
    #? At client memory address , some infomation exist ,message etc..
    
    print"[*] Accepted connection from: %s:%d" % (addr[0],addr[1])
    print addr
    print client
    #boot thread that handle received data
    client_handler = threading.Thread(target=handle_client,args=(client,))
    client_handler.start()