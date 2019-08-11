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
    def get_random_key(length=KEY_SIZE):
        '''Returns random key produced by Crypto.Random.'''
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
        # return Vault.to_bytes(base64.b64decode(data))
        byte_data = base64.b64decode(data)
        assert isinstance(byte_data, bytes)
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
        assert isinstance(data, bytes)
        return data

    def decrypt(self, key, cipher_text):
        '''
        :Arguments:
            key - 16, 24 or 32 bytes long correspond to AES128, 192, 256 respectively.
            chipher_text - bytes.
        :Return: bytes.
        '''
        assert isinstance(key, bytes)
        assert isinstance(cipher_text, bytes)
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
        assert isinstance(data, bytes)

        data += hmac.new(hmac_key, data, digestmod=self.HMAC_DIGESTMOD).digest()
        assert isinstance(data, bytes)
        return data

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
        # return digest  # for unittest

# ==============================================================================
# PBKDF2(password, salt, dkLen=16, count=1000, prf=None)
#     Derive one or more keys from a password (or passphrase).
#
#     This performs key derivation according to the PKCS#5 standard (v2.0),
#     by means of the ``PBKDF2`` algorithm.
#
#     :Parameters:
#      password : string
#         The secret password or pass phrase to generate the key from.
#      salt : string
#         A string to use for better protection from dictionary attacks.
#         This value does not need to be kept secret, but it should be randomly
#         chosen for each derivation. It is recommended to be at least 8 bytes long.
#      dkLen : integer
#         The cumulative length of the desired keys. Default is 16 bytes, suitable for instance for `Crypto.Cipher.AES`.
#      count : integer
#         The number of iterations to carry out. It's recommended to use at least 1000.
#      prf : callable
#         A pseudorandom function. It must be a function that returns a pseudorandom string
#         from two parameters: a secret and a salt. If not specified, HMAC-SHA1 is used.
#
#     :Return: A byte string of length `dkLen` that can be used as key material.
#         If you wanted multiple keys, just break up this string into segments of the desired length.
# ==============================================================================
