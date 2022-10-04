'''
INM363 - this module is implemented to admit new devices into the blockchain
to Monitor and verify whether the blockchain is tamper proof
and to conduct audit proof to verify whether device is already part of the Merkle Tree
'''
import string
import hashlib
from pymerkle import MerkleTree
from pymerkle import Proof
from pymerkle.hashing import HashEngine
from pathlib import Path
from merklelib import export

class MerkleProof:
    def __init__(self):
        #initilize Merkle Tree
        self.tree = MerkleTree()

    def addToTree(self, macAddress = '', featureDevice = '', deviceName = ''):
        # add the devices to the Merkle Tree
        print(macAddress, featureDevice, deviceName)
        if not (macAddress and featureDevice and deviceName):
            return "Device not added. Please enter all the required fields."
        data = "{}{}{}".format(macAddress, featureDevice, deviceName).encode('utf8')
        self.tree.encrypt(data)
        mtree = self.tree
        mtreeFolder = Path("//wsl.localhost/Ubuntu-18.04/home/msangha/blockchain")
        mtreefile = mtreeFolder / "mtree"

        sermtree = self.tree.serialize()
#        export(sermtree, filename=mtreefile, ext='jpg')
        print(mtree)
        print(sermtree)
        print(type(mtree))
        return "Device added to the Merkle Tree"

    def verifyToTree(self, macAddress='', featureDevice = '', deviceName = ''):
        # verify the device in the Merkle Tree
        if not (macAddress and featureDevice and deviceName):
            return "NOT verified. Missing data."
        data = "{}{}{}".format(macAddress, featureDevice, deviceName).encode('utf8')
        challenge = HashEngine(**self.tree.get_config()).hash(data)
        state = self.tree.get_root_hash()
        # Get consistency proof
        proof1 = self.tree.generate_consistency_proof(challenge=state)
        # Audit proof
        #proof2 = self.tree.generate_audit_proof(challenge).serialize()['body']['commitment']
        proof2 = str(self.tree.generate_audit_proof(challenge)).replace("\n", "</br>")
        proof3 = self.tree.generate_audit_proof(challenge)
        print(proof1)
        print(proof2)
        try:
            result = proof3.verify()
            return ["Audit proof - Device verified", proof2]
        except Exception:
            return "NOT verified"

    @property
    def getconsistency(self):
        state = self.tree.get_root_hash()
        #hashproof1 = self.tree.generate_consistency_proof(challenge=state).serialize()['body']['commitment']
        hashproof1 = str(self.tree.generate_consistency_proof(challenge=state)).replace("\n","</br>")
        return hashproof1
    @property
    def getState(self):
        try:
            return self.tree.get_root_hash().decode("utf-8")
        except:
            return 'Root hash not found'
    @property
    def getTree(self):
        data = str(self.tree).replace("\n", "</br>")
        return data
        # print(self.tree)
        #data = self.tree.serialize()
        #return data['hashes']
        #return data

# if __name__ == "__main__":
#     obj = MerkleProof()
#     obj.addToTree("a", "b", "c")
#     print(obj.verifyToTree("a", "b", "c"))
#     print(obj.getTree)
