#!/usr/bin/env python

import sys
import socket
import threading

def server_loop(local_host, local_port, remote_host, remote_port,
                receive_first):
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        server.bind((local_host, local_port))
    except:
        print "[!!] Failed to listen on %s:%d" % (local_host, local_port)
        print "[!!] Check for other listening sockets or correct permissions"
        sys.exit(0)
        
    print "[*] Listening on %s:%d" % (local_host, local_port)
    
    server.listen(5)
    
    while True:
        client_socket, addr = server.accept()
        # addr:(ip addr, port number)
        
        # show information of connection from local
        print "[==>] Received incoming connection from %s:%d" % (addr[0], addr[1])
        
        # start thread to communicate to remote host
        proxy_thread = threading.Thread(target=proxy_handler,
                                        args=(client_socket, remote_host,
                                              remote_port, receive_first))
        proxy_thread.start()
        
def main():
    # interpret argments of commandline
    if len(sys.argv[1:]) != 5:
        print "Usage: ./proxy.py [localhost] [localport] [remotehost] [receive_first]"
        print "Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True"
        sys.exit(0)
        
    # setting to listen correspondense on localside
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    
    # setting on remote side
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    
    # specify if it accepts datas before sending datas to remote side
    receive_first = sys.argv[5]
    
    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False
    
    # start socket of waiting correspondense
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    
    # connect to remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))
    
    # accept data from remote host if needed
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)
        
        # path data to a function to handle accepted data
        remote_buffer = response_handler(remote_buffer)
        
        # send data to local side if there is
        if len(remote_buffer):
            print "[<==] Sending %d bytes to localhost." % len(remote_buffer)
            
            client_socket.send(remote_buffer)
    # start to
    # accept from local, send to remote, send to local
    while True:
        
        # accept data from localhost
        local_buffer = receive_from(client_socket)
        
        if len(local_buffer):
            
            print "[==>] Received %d bytes from localhost." % len(local_buffer)
            
            hexdump(local_buffer)
            
            # path data to the function of request handler
            local_buffer = request_handler(local_buffer)
            
            # send data to remotehost
            remote_socket.send(local_buffer)
            print "[==>] Sent to remote."
            
        # accept response
        remote_buffer = receive_from(remote_socket)
        
        if len(remote_buffer):
            print "[<==] Received %d bytes from remote." % len(remote_buffer)
            
            hexdump(remote_buffer)
            
            #path data to the function of response handler
            remote_buffer = response_handler(remote_buffer)
            
            # send response to local side
            client_socket.send(remote_buffer)
            
            print "[<==] Sent to localhost."
            
        # close connect if data don't come from local and remote host
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print "[*] No more data. Closing connections."
            
            break
        
# the function that remake hexdump and show
# the code got from the comment frame in following URL
# http://code.activestate.com/recipes/142812-hex-dumper/
def hexdump(src, length = 16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    
    for i in xrange(0, len(src), length):
        s =src[i:i+length]
        hexa = b' '.join(["%0*X" % (digits,ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa,text) )
        
    print b'\n'.join(result)
    
def receive_from(connection):
    
    buffer = ""
    
    # set timeout 2 seconds
    connection.settimeout(2)
    
    try:
        # accept data and store in buffer until timeout or data is over
        while True:
            data = connection.recv(4096)
            
            if not data:
                break
            
            buffer += data
            
    except:
        pass
    
    return buffer

def request_handler(buffer):
    # transform packet
    return buffer

def response_handler(buffer):
    # transform packet
    return buffer


main()