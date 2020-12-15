from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import hashlib

class AesCryptoGraphy:
    def __init__(self, password, mode = AES.MODE_CBC):
        '''
        Since password can be of variable length, 
        Hashing the password to create a 32 bytes or 256 bits key
        32 bytes/128 bits key is used to perform AES-256 Algorithm
        ''' 
        key = hashlib.sha256(password.encode()).digest()
        #saving mode of encryption for class instance
        self.mode = mode
        #Creating an AES object for encryption
        self.cipher = AES.new(key, self.mode)
        #Saving the initialisation vector for class instance
        self.iv = self.cipher.iv
        #Creating an AES object for decryption
        self.decipher = AES.new(key, self.mode, self.iv)

    def encrypt(self, plainData):
        #Converting plainData from string to bytes format
        isString = False
        if type(plainData) != bytes:
            isString = True
            plainData = plainData.encode()
        #Encryption Process
        plainData = pad(plainData, AES.block_size)
        cipherData = self.cipher.encrypt(plainData)
        #Converting cipherData from bytes to string format
        cipherData = b64encode(cipherData)
        return cipherData.decode() if isString else cipherData

    def decrypt(self, cipherData):
        #Converting cipherData from string to bytes format
        isString = False
        if type(cipherData) != bytes:
            isString = True
            cipherData = cipherData.encode()
        cipherData = b64decode(cipherData)
        #Decryption Process
        decryptedData = self.decipher.decrypt(cipherData)
        decryptedData = unpad(decryptedData, AES.block_size)
        #Converting decryptedData from bytes to string format
        #decryptedData = decryptedData.decode()
        return decryptedData.decode() if isString else decryptedData

def splitExtension(fullpath):
    import os
    from pathlib import Path

    #Making necessary opeartions in the string to take are of escape characters and slashes
    fullpath = repr(fullpath)[1:-1].replace("\\x", "\\\\")


    fullpath = Path(fullpath)

    filename, ext = os.path.splitext(fullpath)
    return filename, ext

if __name__ == "__main__":
    password = input("Give me a password: ").strip()
    cryptographer = AesCryptoGraphy(password)
    #plainText = input("What's your secret message: \n")
    filepath = "AES Cryptographer\Dataset\Text\SomeText.txt"
    filename, ext = splitExtension(filepath)

    with open(filename+ext, "rb") as d:
        plainText = d.read()
        encrypted = cryptographer.encrypt(plainText)
        #print("Encrypted Text:",encrypted)
        with open(filename+ext+".enc", "wb") as e:
            e.write(encrypted)
    print("Encryption Done")

    with open(filename+ext+".enc", "rb") as d:
        encrypted = d.read()
        decrypted = cryptographer.decrypt(encrypted)
        with open(filename+"_Decrypted"+ext, "wb") as e:
            e.write(decrypted)
    print("Decryption Done")


