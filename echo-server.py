# echo-server.py

import socket
from vcgencmd import Vcgencmd


HOST = "192.168.1.105"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

file1 = open("mypi.txt","r+")
file1info = file1.read()

def getserial():
   # Extract serial from cpuinfo file
   cpuserial = "0000000000000000"
   try:
     f = open('/proc/cpuinfo','r')
     for line in f:
      if line[0:6]=='Serial':
        cpuserial = line[10:26]
     f.close()
   except:
     cpuserial = "ERROR000000000"
   return cpuserial

print("waiting for client to connect ...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
#

    output = getserial()

#
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(output.encode())
