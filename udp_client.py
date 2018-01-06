# -*- coding: utf-8 -*-

import socket

target_host = "127.0.0.1"
target_port = 80

#make a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#AF_INET is setting to use IPv4, SOCK_DGRAM is to use UDP

#have not to preserve connection

#send data
client.sendto("AAABBBCCC",(target_host, target_port))

#recieve data
data, addr = client.recvfrom(4096)

#return value are the data and the addres of the host

print data
