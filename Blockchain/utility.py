'''
INM363 - This module is created to receive features from RaspberryPi which is set up as a server
'''
import socket
from fuzzywuzzy import process
import pickle
from Decryption import DataDecryption as RSA_AES_DATADECRYPTION

#ec import start
from ecdsa import SigningKey,VerifyingKey, NIST384p
import binascii
import sys
import re
#pip install fastecdsa
# sudo apt-get install python-dev libgmp3-dev
#ec import end

def dataDecryption(data):
    text = RSA_AES_DATADECRYPTION(
        encrypt_text = data['encrypt_text'],
        encrypt_key = data['encrypt_key']
        )
    h = str(text).encode('utf8')
    signature = bytes.fromhex(data['signature'])
    verification_key = bytes.fromhex(data['verification_key'])
    #print(verification_key)
    sk = SigningKey.from_string(verification_key, curve=NIST384p)
    valid = sk.verifying_key.verify(signature, h)
    if valid:
        return text
    else:
        return "Error ! signature not matched ."
    return text

def getData():
    HOST = "192.168.1.103" # The server's hostname or IP address
    PORT = 65432 # The port used by the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(b"Hello, world")
        data = s.recv(5120)
        print("data received")

        try:
#           decodeddata = data.decode("utf-8")
            decodeddata = data
            print("data dumped")
        except:
            decodeddata = data

        data = pickle.loads(decodeddata)
        print("data loads")
        decodeddata = dataDecryption(data)
        print("decodeddata")
        return decodeddata

def getParsedData(filterName='rfeatures'):
    data = getData()
    # try:
    #     data = getData()
    # except:
    #     data = "Aug 9 2022 13:44:40 \nCopyright (c) 2012 Broadcom\nversion 273b410636cf8854ca35af91fd738a3d5f8b39b6 (clean) (release) (start)\n\nTemperature - 44.8\nMemory_Arm_CPU - 948\nMemory_GPU - 76Core_Volts - 0.88\nSDRAMc_Volts - 1.1\nSDRAMi_Volts - 1.1\nSDRAMp_Volts - 1.1Clock_Arm - 1800404352\nClock_HDMI - 0Serial - 1000000044a69916Hardware - BCM2711\nModel - aspberry Pi 4 Model B Rev MAC address - <_io.TextIOWrapper name='/sys/class/net/eth0/address' mode='r' encoding='UTF-8'>"
    parsed = data.split('Variable-Data')
    parsed1 = [i for i in parsed[0].split("\n") if i.strip()]
    parsed2 = [i for i in parsed[1].split("\n") if i.strip()]
    if filterName.lower() == 'rfeatures':
        return parsed1, parsed2
    else:
        try:
            filtereddata = process.extractOne(filterName, parsed)[0]
        except:
             filtereddata = 'not found'
        return [filtereddata]

#print(getData())