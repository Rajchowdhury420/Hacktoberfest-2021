import os
import sys
import base64
from Crypto.Cipher import AES
key = b'keytamilctf2021!'
ct = 'oPgiWmZzdeMhyA80iS9c6la2TlIuIJ1HFRAEvH+8zgo='
base = base64.b64decode(ct)
decipher = AES.new(key, AES.MODE_ECB)
pt = decipher.decrypt(base)
print(pt)
