from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from hashlib import sha256

def aes_cbc_encrypt(password: str, data: bytes) -> bytes:
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=sha256)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return salt + iv + ct