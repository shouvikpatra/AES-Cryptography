from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

class AesCryptoGraphy:
    def __init__(self, key):
        pass


key = b"mysecretpassword" #16 bytes or 128 bits key

cipher = AES.new(key, AES.MODE_CBC)

plaintext = "This is a secret message".encode()
plaintext = str(4).encode()


ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

print("PlainText:", plaintext.decode())
iv = cipher.iv
print("CipherText:", ciphertext)

decipher = AES.new(key, AES.MODE_CBC, iv)
decryptedText = unpad(decipher.decrypt(ciphertext), AES.block_size).decode()
print("Decrypted Text:",decryptedText)
