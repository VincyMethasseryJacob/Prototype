from Crypto.PublicKey import RSA

def create_private_key():
    key = RSA.generate(2048)
    return key.export_key(format='PEM').decode('utf-8')