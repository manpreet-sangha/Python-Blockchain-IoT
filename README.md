# Blockchain Python tutorial
* Source Code for my blog post: [A Practical Introduction to Blockchain with Python](http://adilmoujahid.com/posts/2018/03/intro-blockchain-bitcoin-python/)

## Important: This project is for educational purposes only and the source code shouldn't be use in production as it doesn't have good security, doesn't scale well and lacks many important features.

# 02/10/2022 - Manpreet Sangha - Most of the code changes are from publicly available code repos 
# Adapted to admit BLE IoT devices into the blockchain
# Implemented endpoints to scan BLE devices, Merkle Tree demo for audit proof of IoT devices in the blockchain & consistency check of the blockchain ledgers, extract  data from RaspberryPi
# Enhanced the encryption algorithm from RSA to hybrid AES scheme where AES session key is encrypted with RSA
# Replaced RSA signatures with ECDSA signatures and used NIST curves with SHA256 hashing.
#


<div style="display:block;margin:auto;height:80%;width:80%">
  <img src="blockchain-simulation.gif">
</div>

The github repository contains a basic implementation of a blockchain and its client using Python. This blockchain has the following features:

- Possibility of adding multiple nodes to the blockchain
- Proof of Work (PoW)
- Simple conflict resolution between nodes
- Transactions with RSA encryption

The blockchain client has the following features:

- Wallets generation using Public/Private key encryption (based on RSA algorithm)
- Generation of transactions with RSA encryption 

This github repository also contains 2 dashboards: 

- "Blockchain Frontend" for miners 
- "Blockchain Client" for users to generate wallets and send coins 


# Dependencies

- Works with ```Python 3.6``` 
- [Anaconda's Python distribution](https://www.continuum.io/downloads) contains all the dependencies for the code to run.

# How to run the code

1. To start a blockchain node, go to ```blockchain``` folder and execute the command below:
```python blockchain.py -p 5000```
2. You can add a new node to blockchain by executing the same command and specifying a port that is not already used. For example, ```python blockchain.py -p 5001```
3. TO start the blockchain client, go to ```blockchain_client``` folder and execute the command below:
```python blockchain_client.py -p 8080```
4. You can access the blockchain frontend and blockchain client dashboards from your browser by going to localhost:5000 and localhost:8080



# Visit my Blog : http://adilmoujahid.com
