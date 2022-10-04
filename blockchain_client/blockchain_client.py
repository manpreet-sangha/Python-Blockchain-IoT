'''
title           : blockchain_client.py
description     : A blockchain client implemenation, with the following features
                  - Wallets generation using Public/Private key encryption (based on RSA algorithm)
                  - Generation of transactions with RSA encryption      
author          : Adil Moujahid
date_created    : 20180212
date_modified   : 20180309
version         : 0.3
usage           : python blockchain_client.py
                  python blockchain_client.py -p 8080
                  python blockchain_client.py --port 8080
python_version  : 3.6.1
Comments        : Wallet generation and transaction signature is based on [1]
References      : [1] https://github.com/julienr/ipynb_playground/blob/master/bitcoin/dumbcoin/dumbcoin.ipynb
'''
import base64
import hashlib
from collections import OrderedDict

import binascii
import codecs

import Crypto
import Crypto.Hash.SHA256
import Crypto.Random
import ecdsa.ecdsa
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import requests
from flask import Flask, jsonify, request, render_template
from ecdsa import SigningKey, VerifyingKey, NIST256p, NIST521p
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from pathlib import Path
#ec import start
# from fastecdsa import curve, ecdsa, keys
# from fastecdsa.encoding.der import DEREncoder
# import fastecdsa.encoding.sec1
# import fastecdsa
import binascii
import sys
import re
#pip install fastecdsa
# sudo apt-get install python-dev libgmp3-dev
#ec import end

class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'value': self.value})

    @property
    def sign_transaction(self):
        """
        INM363 - Sign transaction with ECDSA instead of RSA
        """
        private_key = self.sender_private_key
        print(private_key)
        h = str(self.to_dict()).encode('utf8')

        final_private_key = bytes.fromhex(private_key)
        print(final_private_key)
        sk = SigningKey.from_string(final_private_key, curve=NIST521p)
        sig = sk.sign(h)
        print("Signature: ")
        print(sig)
        print(sig.hex())
        print(str(len(sig)))
        print(type(sig))
        return sig.hex()

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')

# INM363 Modified code to use Elliptic Curve Digital Signature Algorithm ECDSA

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    sk = SigningKey.generate(curve=NIST521p)
    vk = sk.verifying_key
    keysFolder = Path("//wsl.localhost/Ubuntu-18.04/home/msangha/blockchain")
    vkfile = keysFolder / "public-wallet.pem"
    skfile = keysFolder / "private-wallet.pem"
    with open(vkfile, "wb") as f:
        f.write(vk.to_pem())
    with open(skfile, "wb") as f:
        f.write(sk.to_pem())

    private_key = sk.to_string().hex()
    final_public_key = vk.to_string().hex()
    # print(int(hex(private_key), base=16))
    response = {
        'private_key': private_key,
        'public_key': final_public_key
    }
    return jsonify(response), 200


# random_gen = Crypto.Random.new().read
# private_key = RSA.generate(1024, random_gen)
# public_key = private_key.publickey()
# response = {
#     'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
#     'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
# }
#
# return jsonify(response), 200


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
	
    sender_address = request.form['sender_address']
    sender_private_key = request.form['sender_private_key']
    recipient_address = request.form['recipient_address']
    value = request.form['amount']

    transaction = Transaction(sender_address, sender_private_key, recipient_address, value)
    print(type(transaction))
    print(transaction)
    response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction}

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)