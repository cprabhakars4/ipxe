#AES_GCM python implementaion 

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.number import long_to_bytes

number = 1
flag = open("sentance.txt", "rb").read()
key = scrypt(long_to_bytes(number), b"code", 32, N = 2 ** 10, r = 8, p = 1)
HexMyKey = key.hex()
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(flag)

enc = cipher.nonce + ciphertext + tag
HexEncryptedOriginalMessage = enc.hex()