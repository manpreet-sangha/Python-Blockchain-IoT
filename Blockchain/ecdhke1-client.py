from ecdsa import ECDH, NIST256p

ecdh = ECDH(curve=NIST256p)
local_private_key = ecdh.generate_private_key()
local_public_key = ecdh.get_public_key()

print("client private key " + local_private_key.to_string().hex())
print("client public key " + local_public_key.to_string().hex())
