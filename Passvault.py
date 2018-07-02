# encoding:utf-8

# Main file for Passvault
# Contains Passvault methods: encrypt/decrypt.


import base64
import hashlib
import hmac

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol import KDF

class Vault():

    AES_MODE = AES.MODE_CBC   # Input strings must be a multiple of 16 in length
    # AES_MODE = AES.MODE_CFB
    # AES_MODE = AES.MODE_OFB   # Input strings must be a multiple of 16 in length
    # AES_MODE = AES.MODE_CTR   # 'counter' keyword parameter is required with CTR mode
    # AES_MODE = AES.MODE_ECB   # Input strings must be a multiple of 16 in length
    KEY_SIZE = 32 # to be 32 bytes, not 256 !!
    SALT_SIZE = 16
    HMAC_DIGESTMOD = hashlib.sha3_256
    HMAC_HASH_SIZE = 32
    KDF_COUNT = 10000
    DK_LEN = 32
    VAULT_ID_LENGHT = 32

    @staticmethod
    def get_random_key(length=KEY_SIZE): # self.KEY_SIZE
        """Returns random key produced by Crypto.Random."""
        return Random.new().read(length)

    def pre_encrypt_data(self, data):
        '''
        :Arguments: string or bytes
        :Return: bytes - data with padding applied.
        '''
        data = self.to_bytes(data)
        assert isinstance(data, bytes)
        padding = AES.block_size - len(data) % AES.block_size
        data += bytes([padding]) * padding
        assert isinstance(data, bytes)
        return data

    def post_encrypt_data(self, data):
        '''
        :Arguments: bytes
        :Return: base64 encoded data.
        # return bytes base64 object
        '''
        # shoult method to_str() be used in returning values??
        return self.encode_base64(data)

    def encrypt_enc_key(self, password, enc_key):
        """
        dkLen=32 corresponds to AES256 key (32 bytes).
        Return (kdf_salt, hmac_salt, encrypted data, hmac(kdf_salt, hmac_salt, encrypted data)).
        hashlib.sha3_256 produces 32 bytes hash.
        """

        kdf_salt = self.kdf_salt()
        hmac_salt = self.hmac_salt()
        iv = self.iv()

        encryption_key = KDF.PBKDF2(password, kdf_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, prf=None)
        hmac_key = KDF.PBKDF2(password, hmac_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, prf=None)
        encrypted_enc_key = self.encrypt(encryption_key, iv, enc_key)

        data = kdf_salt + hmac_salt + encrypted_enc_key
        assert isinstance(data, bytes)

        data += hmac.new(hmac_key, data, digestmod=self.HMAC_DIGESTMOD).digest()
        assert isinstance(data, bytes)
        return data

    # should decoding from base64 be implemented??
    def pre_decrypt_data(self, data):
        '''
        :Arguments: base64 string
        :Return: bytes - data derived from base64
        '''
        data = self.decode_base64(data)
        data = self.to_bytes(data)
        return data

    # to check is this function is proprly working during random data handling?
    def post_decrypt_data(self, data):
        '''
        :Arguments: bytes
        :Return: bytes
        Remove padding.
        '''
        padding = data[-1]
        # should to_str function work only this not random data, e.g. letters, words, etc?
        # return self.to_str(data[:-padding])
        return data[:-padding] # even random data will be processed

    def decrypt_enc_key(self, password, data):
        kdf_salt = data[:self.SALT_SIZE]
        hmac_salt = data[self.SALT_SIZE:self.SALT_SIZE*2]

        encryption_key = KDF.PBKDF2(password, kdf_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, prf=None)
        hmac_key = KDF.PBKDF2(password, hmac_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, prf=None)

        hmac_ = hmac.new(hmac_key, data[:-self.HMAC_HASH_SIZE], digestmod=self.HMAC_DIGESTMOD).digest()

        assert isinstance(hmac_, bytes)
        assert isinstance(data[-self.HMAC_HASH_SIZE:], bytes)

        if hmac_ != data[-self.HMAC_HASH_SIZE:]:
            raise Exception('Bad hmac!')

        enc_key = self.decrypt(encryption_key, data[self.SALT_SIZE*2:-self.HMAC_HASH_SIZE])
        return enc_key

    def encrypt(self, key, iv, plain_text):
        '''
        :Parameters:
            key : byte string
                The secret key to use in the symmetric cipher.
                It must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.
            iv : byte string
                The initialization vector to use for encryption or decryption.
            plain_text: byte string
                Piece of data to encrypt
        :Return:
            encrypted data as a byte string
        '''
        cipher = AES.new(key, self.AES_MODE, iv)
        return iv + cipher.encrypt(plain_text)

    def decrypt(self, key, cipher_text):
        '''
        :Arguments:
            key - 16, 24 or 32 bytes long correspond to AES128, 192, 256 respectively
            chipher_text - bytes
        :Return: => bytes
        '''
        iv = cipher_text[:AES.block_size]
        cipher = AES.new(key, self.AES_MODE, iv)
        return cipher.decrypt(cipher_text)[AES.block_size:]

    def iv(self):
        return Random.new().read(AES.block_size)

    def kdf_salt(self):
        return Random.new().read(self.SALT_SIZE)

    def hmac_salt(self):
        return Random.new().read(self.SALT_SIZE)

    @staticmethod
    def encode_base64(data):
        return base64.b64encode(data)

    @staticmethod
    def decode_base64(data):
        return base64.b64decode(data)

    def to_bytes(self, s):
        if isinstance(s, bytes):
            return s
        elif isinstance(s, str):
            return s.encode('utf-8')

    def to_str(self, s):
        if isinstance(s, bytes):
            return s.decode('utf-8')
        elif isinstance(s, str):
            return s

    # to be refactored
    def sign(self, key, entry):
        key = self.to_bytes(key)
        entry = self.to_bytes(entry)
        return hmac.new(key, entry, digestmod=hashlib.sha256).hexdigest()

    def verify(self, key, entry, signature):
        key = self.to_bytes(key)
        entry = self.to_bytes(entry)
        digest = hmac.new(key, entry, digestmod=hashlib.sha256).hexdigest()
        if digest != signature:
            raise Exception('Bad signature!')
        return None
        # return digest  # for unittest
