from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generate RSA key pair
key = RSA.generate(2048)
pub_key = key.publickey()

# Alice signs the message with her private key
message = b'Transfer $1000 to Mark'
h = SHA256.new(message)
signature = pkcs1_15.new(key).sign(h)

# Bob verifies the signature using Alice's public key
try:
    pkcs1_15.new(pub_key).verify(h, signature)
    print('Verification result: VALID signature')
except (ValueError, TypeError):
    print('Verification result: INVALID')

# Verify against a tampered message
tampered = b'Transfer $1000 to Oscar'
h2 = SHA256.new(tampered)
try:
    pkcs1_15.new(pub_key).verify(h2, signature)
    print('Tampered message: VALID')
except (ValueError, TypeError):
    print('Tampered message: SIGNATURE INVALID (tampering detected)')
