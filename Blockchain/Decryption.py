'''
INM363 - this module implements hybrid asymmetric AES-RSA decryption algorithm
'''
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from config import Config


# pip install pycryptodome==3.10.1


class AESCipher:
    def __init__(self, key):
        self.key = key
        self.iv = key

    def encrypt(self, raw):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(self.__pad(raw).encode())).decode()

    def decrypt(self, enc):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.__unpad(cipher.decrypt(base64.b64decode(enc)).decode())

    def __pad(self, text):
        text_length = len(text)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def __unpad(self, text):
        pad = ord(text[-1])
        return text[:-pad]


class RSACipher():
    def encrypt(self, key, raw):
        public_key = RSA.importKey(base64.b64decode(key))
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, key, enc):
        private_key = RSA.importKey(base64.b64decode(key))
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        return cipher.decrypt(base64.b64decode(enc))

    def sign(self, key, text):
        private_key = RSA.importKey(base64.b64decode(key))
        hash_value = SHA256.new(text)
        signer = PKCS1_v1_5.new(private_key)
        signature = signer.sign(hash_value)
        return base64.b64encode(signature)

    def verify(self, key, text, signature):
        public_key = RSA.importKey(base64.b64decode(key))
        hash_value = SHA256.new(text)
        verifier = PKCS1_v1_5.new(public_key)
        return verifier.verify(hash_value, base64.b64decode(signature))


def DataDecryption(encrypt_text, encrypt_key):
    aes_key = get_random_bytes(16)
    aes_cipher = AESCipher(aes_key)
    rsa_cipher = RSACipher()
    aes_key = rsa_cipher.decrypt(Config.SERVER_PRIVATE_KEY, encrypt_key)
    print("Recovered AES_KEY")
    print(aes_key)
    aes_cipher = AESCipher(aes_key)
    decrypt_text = aes_cipher.decrypt(encrypt_text)
    print("Decrypted text")
    print(decrypt_text)
    return decrypt_text
# if __name__ == "__main__":
#     encrypt_text= "c1BqW/gZX9AP2QWwXrXvwA=="
#     encrypt_key = b'dLdoEWJ+QE1IoLSARIVVgwvyxLztGom5caUtb+1ZUnX6fMpkgl0cYE8EIOI131uQM0hYUYzVV33Sg4o4depIMqhDwfoeBwHA2OAiupYz0kdIseKIphMlzy3yYZ1rvFNpdy9J7n2IK9zsNzR1+QpBWSpbcxTKoGCkKBiDPHcOJic='

#     text = DataDecryption(encrypt_text, encrypt_key)

#     print(text)