import hashlib

PUB = "keys/public_key.pem"

with open(PUB, "rb") as f:
    b = f.read()

print(hashlib.sha256(b).hexdigest())