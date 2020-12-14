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
        if type(plainData) != bytes:
            plainData = plainData.encode()
        
        #Encryption Process
        plainData = pad(plainData, AES.block_size)
        cipherData = self.cipher.encrypt(plainData)
        #Converting cipherData from bytes to string format
        cipherData = b64encode(cipherData).decode()
        return cipherData

    def decrypt(self, cipherData):
        #Converting cipherData from string to bytes format
        if type(cipherData) != bytes:
            cipherData = b64decode(cipherData)
        #Decryption Process
        decryptedData = self.decipher.decrypt(cipherData)
        decryptedData = unpad(decryptedData, AES.block_size)
        #Converting decryptedData from bytes to string format
        decryptedData = decryptedData.decode()
        return decryptedData


if __name__ == "__main__":
    password = input("Give me a password: ").strip()
    cryptographer = AesCryptoGraphy(password)
    plainText = input("What's your secret message: \n")
    encrypted = cryptographer.encrypt(plainText)
    print("Encrypted Text:",encrypted)

    decrypted = cryptographer.decrypt(encrypted)
    print("Decrypted Text:", decrypted)
    if plainText == decrypted:
        print(True)


