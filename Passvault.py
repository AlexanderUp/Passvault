# encoding:utf-8
# Main file for Passvault
# Contains Passvault methods: encrypt/decrypt.


import base64
import hashlib
import hmac


from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Protocol import KDF


class Vault():

    AES_MODE = AES.MODE_CBC   # Input strings must be a multiple of 16 in length
    KEY_SIZE = 32 # to be 32 bytes, not 256 !!
    SALT_SIZE = 16
    HMAC_DIGESTMOD = hashlib.sha3_256
    HMAC_HASH_SIZE = 32
    KDF_COUNT = 10000
    DK_LEN = 32
    VAULT_ID_LENGHT = 32

    @staticmethod
    def get_random_key(length=KEY_SIZE):
        '''Returns random key produced by Crypto.Random.''' # Cryptodome currently in use
        return Random.new().read(length)

    @staticmethod
    def to_bytes(s):
        if isinstance(s, bytes):
            return s
        elif isinstance(s, str):
            return s.encode('utf-8')

    @staticmethod
    def to_str(s):
        if isinstance(s, bytes):
            return s.decode('utf-8')
        elif isinstance(s, str):
            return s

    @staticmethod
    def get_random_key_human_readable(key):
        return Vault.to_str(base64.b16encode(key))

    @staticmethod
    def encode_base64(data):
        '''Encode the bytes-like object using Base64 and return a str object.'''
        return Vault.to_str(base64.b64encode(data))

    @staticmethod
    def decode_base64(data):
        '''
        Decode the Base64 encoded bytes-like object or ASCII string.
        The result is returned as a bytes object.
        '''
        byte_data = base64.b64decode(data)
        return byte_data

    def iv(self):
        return Random.new().read(AES.block_size)

    def pre_encrypt_data(self, data):
        '''
        :Arguments: string or bytes.
        :Return: bytes - data with padding applied.
        '''
        data = self.to_bytes(data)
        padding = AES.block_size - len(data) % AES.block_size
        data += bytes([padding]) * padding
        return data

    def encrypt(self, key, iv, plain_text):
        '''
        :Parameters:
            key : byte string.
                The secret key to use in the symmetric cipher.
                It must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.
            iv : byte string.
                The initialization vector to use for encryption or decryption.
            plain_text: byte string.
                Piece of data to encrypt.
        :Return:
            encrypted data as a byte string.
        '''
        cipher = AES.new(key, self.AES_MODE, iv)
        return iv + cipher.encrypt(plain_text)

    def post_encrypt_data(self, data):
        '''
        !!! Method used to store encrypted data in database.
        :Arguments: bytes.
        :Return: bytes - base64 encoded data.
        '''
        return self.encode_base64(data)

    def pre_decrypt_data(self, data):
        '''
        !!! Method used to handle data retrieved from database.
        :Arguments: base64 bytes.
        :Return: bytes - data derived from base64.
        '''
        data = self.to_bytes(data)
        data = self.decode_base64(data)
        return data

    def decrypt(self, key, cipher_text):
        '''
        :Arguments:
            key - 16, 24 or 32 bytes long correspond to AES128, 192, 256 respectively.
            chipher_text - bytes.
        :Return: bytes.
        '''
        iv = cipher_text[:AES.block_size]
        cipher = AES.new(key, self.AES_MODE, iv)
        return cipher.decrypt(cipher_text[AES.block_size:])

    def post_decrypt_data(self, data):
        '''
        :Arguments: bytes.
        :Return: bytes.
        Remove padding.
        '''
        padding = data[-1]
        return data[:-padding]

    def kdf_salt(self):
        return Random.new().read(self.SALT_SIZE)

    def hmac_salt(self):
        return Random.new().read(self.SALT_SIZE)

    def encrypt_enc_key(self, password, enc_key):
        '''
        dkLen=32 corresponds to AES256 key (32 bytes).
        Return (kdf_salt, hmac_salt, encrypted data, hmac(kdf_salt, hmac_salt, encrypted data)).
        hashlib.sha3_256 produces 32 bytes hash.
        '''
        kdf_salt = self.kdf_salt()
        hmac_salt = self.hmac_salt()
        iv = self.iv()

        encryption_key = KDF.PBKDF2(password, kdf_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, prf=None)
        hmac_key = KDF.PBKDF2(password, hmac_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, prf=None)
        encrypted_enc_key = self.encrypt(encryption_key, iv, enc_key)

        data = kdf_salt + hmac_salt + encrypted_enc_key
        data += hmac.new(hmac_key, data, digestmod=self.HMAC_DIGESTMOD).digest()
        return data

    def decrypt_enc_key(self, password, data):
        kdf_salt = data[:self.SALT_SIZE]
        hmac_salt = data[self.SALT_SIZE:self.SALT_SIZE*2]

        encryption_key = KDF.PBKDF2(password, kdf_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, prf=None)
        hmac_key = KDF.PBKDF2(password, hmac_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, prf=None)

        hmac_ = hmac.new(hmac_key, data[:-self.HMAC_HASH_SIZE], digestmod=self.HMAC_DIGESTMOD).digest()

        if hmac_ != data[-self.HMAC_HASH_SIZE:]:
            raise Exception('Bad hmac!')

        enc_key = self.decrypt(encryption_key, data[self.SALT_SIZE*2:-self.HMAC_HASH_SIZE])
        return enc_key

    def set_encrypted_data(self, key, data):
        '''Combine some encryption methods in one call.'''
        iv = self.iv()
        plain_text = self.pre_encrypt_data(data)
        encrypted_data = self.encrypt(key, iv, plain_text)
        post_encrypted_data = self.post_encrypt_data(encrypted_data)
        return post_encrypted_data

    def get_decrypted_data(self, key, encrypted_data):
        '''Combine some decryption methods in one call.'''
        pre_decrypted_data = self.pre_decrypt_data(encrypted_data)
        decrypted_data = self.decrypt(key, pre_decrypted_data)
        post_decrypted_data = self.post_decrypt_data(decrypted_data)
        return post_decrypted_data

# ==============================================================================
    # to be refactored
    # salt to be added, otherwise same entry always will produce same hmac
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
# ==============================================================================
