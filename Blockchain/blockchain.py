"""
title           : blockchain.py
description     : A blockchain implemenation
author          : Adil Moujahid
date_created    : 20180212
date_modified   : 20180309
author          : Manpreet Sangha
date_modified   : 02/10/2022
version         : 0.5
usage           : python blockchain.py
                  python blockchain.py -p 5000
                  python blockchain.py --port 5000
python_version  : 3.6.1
Comments        : The blockchain implementation is mostly based on [1].
                  I made a few modifications to the original code in order to add RSA encryption to the transactions
                  based on [2], changed the proof of work algorithm, and added some Flask routes to interact with the
                  blockchain from the dashboards
References      : [1] https://github.com/dvf/blockchain/blob/master/blockchain.py
                  [2] https://github.com/julienr/ipynb_playground/blob/master/bitcoin/dumbcoin/dumbcoin.ipynb
"""

from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
from utility import getParsedData
import requests
from flask import Flask, jsonify, request, render_template
from flask import redirect, url_for
from flask_cors import CORS
from merkleTree import MerkleProof
import bluetooth
from ecdsa import SigningKey, VerifyingKey, NIST256p, NIST521p, BadSignatureError
from pathlib import Path

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self):

        self.transactions = []
        self.merkleProofObject = MerkleProof()
        self.chain = []
        self.nodes = set()
        # Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')
        # Create genesis block
        self.create_block(0, '00')

    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        Modified the code to accept bluetooth MAC address as it is as there is no need to parse it as it removes
        the initial three characters out of it
        """

        # Checking node_url has valid format
        parsed_url = urlparse(node_url)
        # use SHA-256 to hash the MAC address, the hashed MAC address will be added to the blockchain
        hashed_url = hashlib.sha256(node_url.encode())
        hex_url = hashed_url.hexdigest()
        print("node_url - " + str(node_url))
        print("The hexadecimal equivalent of MAC-address SHA256 is : " + hex_url)
        print("parsed_url - " + str(parsed_url))
        #        if parsed_url.netloc:
        if node_url:
            print("parsed_url.netloc - " + parsed_url.netloc)
            self.nodes.add(node_url + "    " + hex_url)
        #           self.nodes.add(parsed_url.netloc)\
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            print("parsed_url.path" + parsed_url.path)
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def verify_transaction_signature(self, sender_address, signature, transaction):
        """
        INM363- Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """
        keysFolder = Path("//wsl.localhost/Ubuntu-18.04/home/msangha/blockchain")
        vkfile = keysFolder / "public-wallet.pem"
        skfile = keysFolder / "private-wallet.pem"
        vk = VerifyingKey.from_pem(open(vkfile).read())
        print("0")
        print(vk)
        print("1")
        public_key = bytes.fromhex(sender_address)
        sk = VerifyingKey.from_string(public_key, curve=NIST521p)
        signature = bytes.fromhex(signature)
        print("ECDSA signature")

        h = str(transaction).encode('utf8')
        try:
            vk.verify(signature, h)
            print("good signature")
        except BadSignatureError:
            print("BAD SIGNATURE")

        return sk.verify(signature, h)
# '''To be commented '''
#         assert pk.
#         public_key = RSA.importKey(binascii.unhexlify(sender_address))
#         verifier = PKCS1_v1_5.new(public_key)
#         h = SHA.new(str(transaction).encode('utf8'))
#         return verifier.verify(h, binascii.unhexlify(signature))

    def submit_transaction(self, sender_address, recipient_address, value, signature):
        """
        Add a transaction to transactions array if the signature verified
        """
        transaction = OrderedDict({'sender_address': sender_address,
                                   'recipient_address': recipient_address,
                                   'value': value})

        # Reward for mining a block
        if sender_address == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        # Manages transactions from wallet to another wallet
        else:
            transaction_verification = self.verify_transaction_signature(sender_address, signature, transaction)
            if transaction_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False

    def create_block(self, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain
        """
        block = {'block_number': len(self.chain) + 1,
                 'timestamp': time(),
                 'transactions': self.transactions,
                 'nonce': nonce,
                 'previous_hash': previous_hash}

        # Reset the current list of transactions
        self.transactions = []

        self.chain.append(block)
        return block

    def hash(self, block):
        """
        Create a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()

        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        """
        Proof of work algorithm
        """
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce

    def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        """
        Check if a hash value satisfies the mining conditions. This function is used within the proof_of_work function.
        """
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def valid_chain(self, chain):
        """
        check if a bockchain is valid
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # print(last_block)
            # print(block)
            # print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            # Delete the reward transaction
            transactions = block['transactions'][:-1]
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            transaction_elements = ['sender_address', 'recipient_address', 'value']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in
                            transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        Resolve conflicts between blockchain's nodes
        by replacing our chain with the longest one in the network.
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            print('http://' + node + '/chain')
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False


# Instantiate the Node
app = Flask(__name__)
CORS(app)

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/configure')
def configure():
    return render_template('./configure.html')


'''
INM363 - Included new function rpifeatures to fetch raspberryPi features
'''


@app.route('/rpifeatures')
def rpifeatures():
    data = request.args.get("name", 'rfeatures')
    received_data1, received_data2 = getParsedData(data)
    print(received_data1)
    print(received_data2)
    return render_template('./rfeatures.html', data={"constantData": received_data1, "variableData": received_data2})

'''
INM363 - get devices start
'''
@app.route('/devices')
def getDevices():
    #    devices =  bluetooth.discover_devices(flush_cache=True,lookup_names = True)
    devices = bluetooth.discover_devices(duration=4, flush_cache=True, lookup_class=True, lookup_names=True)
    print("devices - " + str(devices[0]) + "\n" + str(devices[1]) + "\n" + str(devices[2]))
    return render_template('./devices.html', devices=devices)


@app.route('/devices/scan')
def scanDevices():
    nearby_devices = bluetooth.discover_devices(duration=4, flush_cache=True, lookup_class=True, lookup_names=True)
    print("nearby_devices - " + str(nearby_devices[0]) + "\n" + str(nearby_devices[1]) + "\n" + str(nearby_devices[2]))
    return jsonify(nearby_devices), 200

'''
INM363 - get devices end
'''

# Merkle tree device addition and verification code INM363
@app.route('/devices/tree')
def merkleTreeView():
    return render_template("./verifyDevice.html")


@app.route("/api/merkleTree/add", methods=['POST'])
def merkleTreeAdd():
    values = request.form
    MACAddress = values.get("MACAddress", None)
    features = values.get("features", None)
    device = values.get("device_name", None)
    print(MACAddress + features + device)
    merkleTreeData = blockchain.merkleProofObject.addToTree(MACAddress, features, device)
    print(merkleTreeData)
    message = {
        "merkleTreeData": merkleTreeData
    }
    return jsonify(message), 200


@app.route("/api/merkleTree/verify", methods=['POST'])
def merkleTreeVerify():
    values = request.form
    MACAddress = values.get("MACAddress", None)
    features = values.get("features", None)
    device = values.get("device_name", None)
    merkleTreeDataVerify = blockchain.merkleProofObject.verifyToTree(MACAddress, features, device)
    print("merkleTreeDataVerify[0] - " + "\n" + merkleTreeDataVerify[0])
    print("merkleTreeDataVerify[1] - " + "\n" + merkleTreeDataVerify[1])
    message = {
        "mtreeNotification": merkleTreeDataVerify[0],
        "commitment": merkleTreeDataVerify[1]
    }
    return jsonify(message), 200


@app.route("/api/merkleTree/gethash")
def markleGetHash():
    state = blockchain.merkleProofObject.getState
    msg = {"state": state}
    return jsonify(msg), 200


@app.route("/api/merkleTree/gettree")
def markleGetTree():
    tree = blockchain.merkleProofObject.getTree
    msg = {"tree": tree}
    return jsonify(msg), 200


@app.route("/api/merkleTree/getconsistencyproof")
def markleConsistency():
    constProof = blockchain.merkleProofObject.getconsistency
    msg = {
        "consistency": constProof
    }
    return jsonify(msg), 200


@app.route("/addnodes")
def addnodes():
    mac_address = request.args.get("name", None)
    print("mac_address - " + mac_address)
    if mac_address == None:
        return redirect(url_for('getDevices'))
    nodes = mac_address.replace(" ", "").split(',')
    print("nodes - " + nodes[0] + "\n")
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        print("node - " + node)
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    # return jsonify(response), 201
    return redirect(url_for('getDevices'))


# get devices end======


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['sender_address', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    # Create a new Transaction
    transaction_result = blockchain.submit_transaction(values['sender_address'], values['recipient_address'],
                                                       values['amount'], values['signature'])

    if transaction_result == False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block ' + str(transaction_result)}
        return jsonify(response), 201


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain.transactions

    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()

    # We must receive a reward for finding the proof.
    blockchain.submit_transaction(sender_address=MINING_SENDER, recipient_address=blockchain.node_id,
                                  value=MINING_REWARD, signature="")

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
