# encoding:utf-8
# Main file for Passvault
# Contains Passvault methods: encrypt/decrypt.


import base64
import hashlib
import hmac


from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Protocol import KDF
from Cryptodome.Hash import SHA512


class Vault():

    AES_MODE = AES.MODE_CBC   # Input strings must be a multiple of 16 in length
    KEY_SIZE = 32             # to be 32 bytes, not 256 !!
    SALT_SIZE = 16
    HMAC_DIGESTMOD = hashlib.sha3_256
    HMAC_HASH_SIZE = 32
    KDF_COUNT = 10000
    DK_LEN = 32
    PBKDF_HMAC_HASH_MODULE = SHA512
    VAULT_ID_LENGHT = 32

    @staticmethod
    def get_random_key(length=KEY_SIZE):
        '''
        Returns random key produced by Cryptodome.Random.
        '''
        return Random.new().read(length)

    @staticmethod
    def to_bytes(s):
        if isinstance(s, bytes):
            return s
        elif isinstance(s, str):
            return s.encode('utf-8')
        else:
            raise TypeError('Argument is nor *bytes* neither *str* !')

    @staticmethod
    def to_str(s):
        if isinstance(s, bytes):
            return s.decode('utf-8')
        elif isinstance(s, str):
            return s
        else:
            raise TypeError('Argument is nor *bytes* neither *str* !')

    @staticmethod
    def get_random_key_human_readable(key):
        return Vault.to_str(base64.b16encode(key))

    @staticmethod
    def encode_base64(data):
        '''
        Encodes the bytes-like object using Base64 and return a str object.
        '''
        return Vault.to_str(base64.b64encode(data))

    @staticmethod
    def decode_base64(data):
        '''
        Decode the Base64 encoded bytes-like object or ASCII string.
        The result is returned as a bytes object.
        '''
        bytes_data = base64.b64decode(data)
        return bytes_data

    def init_vault_id(self):
        '''
        Returns string.
        '''
        vault_id = self.get_random_key(length=self.VAULT_ID_LENGHT)
        return self.encode_base64(vault_id)

    def get_iv(self):
        '''
        Returns initialization vector.
        '''
        return Random.new().read(AES.block_size)

    def pre_encrypt_data(self, data):
        '''
        :Arguments: string or bytes.
        :Returns: bytes - data with padding applied.
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
        :Returns:
            encrypted data as a byte string.
        '''
        cipher = AES.new(key, self.AES_MODE, iv)
        return iv + cipher.encrypt(plain_text)

    def post_encrypt_data(self, data):
        '''
        Method used to store encrypted data in database.

        :Arguments: bytes.
        :Returns: string.
        '''
        return self.encode_base64(data)

    def pre_decrypt_data(self, data):
        '''
        Method used to handle data retrieved from database.

        :Arguments: base64 bytes or string.
        :Returns: bytes - data derived from base64.
        '''
        data = self.to_bytes(data)
        data = self.decode_base64(data)
        return data

    def decrypt(self, key, cipher_text):
        '''
        :Arguments:
            key : 16, 24 or 32 bytes long correspond to AES128, 192, 256 respectively.
            chipher_text : bytes.
        :Returns: bytes.
        '''
        iv = cipher_text[:AES.block_size]
        cipher = AES.new(key, self.AES_MODE, iv)
        return cipher.decrypt(cipher_text[AES.block_size:])

    def post_decrypt_data(self, data):
        '''
        Remove padding.

        :Arguments: bytes.
        :Returns: bytes.
        '''
        padding = data[-1]
        return data[:-padding]

    def get_salt(self):
        '''
        Returns salt.
        '''
        return Random.new().read(self.SALT_SIZE)

    def encrypt_master_key(self, master_password, master_key):

        '''
        dkLen=32 corresponds to AES256 key (32 bytes).
        Return (kdf_salt, hmac_salt, encrypted data, hmac(kdf_salt, hmac_salt, encrypted data)).
        hashlib.sha3_256 produces 32 bytes hash.

        :Arguments:
            master_password: string or byte string
            master_key: bytes

        :Returns:
            bytes (total 112 bytes in lenght)

        [
        PBKDF2 :Arguments:
             password: string or byte string
             salt: string or byte string
             dkLen: integer
             count: integer
             prf: callable
             hmac_hash_module: module

        PBKDF2 :Returns:
            A byte string of length ``dkLen`` that can be used as key material.
        ]
        '''

        kdf_salt = self.get_salt()
        hmac_salt = self.get_salt()
        iv = self.get_iv()

        encryption_key = KDF.PBKDF2(master_password, kdf_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, hmac_hash_module=self.PBKDF_HMAC_HASH_MODULE)
        hmac_key = KDF.PBKDF2(master_password, hmac_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, hmac_hash_module=self.PBKDF_HMAC_HASH_MODULE)
        encrypted_master_key = self.encrypt(encryption_key, iv, master_key)

        data = kdf_salt + hmac_salt + encrypted_master_key
        data += hmac.new(hmac_key, data, digestmod=self.HMAC_DIGESTMOD).digest()
        return data

    def decrypt_master_key(self, master_password, data):

        '''
        dkLen=32 corresponds to AES256 key (32 bytes).
        Return (kdf_salt, hmac_salt, encrypted data, hmac(kdf_salt, hmac_salt, encrypted data)).
        hashlib.sha3_256 produces 32 bytes hash.

        :Arguments:
            master_password: string or byte string
            data: bytes

        :Returns:
            bytes

        [
        PBKDF2 :Arguments:
             password: string or byte string
             salt: string or byte string
             dkLen: integer
             count: integer
             prf: callable
             hmac_hash_module: module

        PBKDF2 :Returns:
            A byte string of length ``dkLen`` that can be used as key material.
        ]
        '''

        kdf_salt = data[:self.SALT_SIZE]
        hmac_salt = data[self.SALT_SIZE:self.SALT_SIZE*2]

        encryption_key = KDF.PBKDF2(master_password, kdf_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, hmac_hash_module=self.PBKDF_HMAC_HASH_MODULE)
        hmac_key = KDF.PBKDF2(master_password, hmac_salt, dkLen=self.DK_LEN, count=self.KDF_COUNT, hmac_hash_module=self.PBKDF_HMAC_HASH_MODULE)

        hmac_ = hmac.new(hmac_key, data[:-self.HMAC_HASH_SIZE], digestmod=self.HMAC_DIGESTMOD).digest()

        if hmac_ != data[-self.HMAC_HASH_SIZE:]:
            raise Exception('Bad hmac!')

        master_key = self.decrypt(encryption_key, data[self.SALT_SIZE*2:-self.HMAC_HASH_SIZE])
        return master_key


class PasswordCipher(Vault):

    def init_master_key(self, master_password, master_key):
        '''
        :Arguments:
            master_password: string or byte string
            master_key: bytes string
        :Returns:
            string
        '''
        master_key = self.pre_encrypt_data(master_key)
        encrypted_master_key = self.encrypt_master_key(master_password, master_key)
        encrypted_master_key = self.post_encrypt_data(encrypted_master_key)
        return self.to_str(encrypted_master_key)

    def get_master_key(self, master_password, encrypted_master_key):
        '''
        :Arguments:
            master_password: string or byte string
            encrypted_master_key: string or bytes string
        :Returns:
            bytes
        '''
        encrypted_master_key = self.pre_decrypt_data(encrypted_master_key)
        master_key = self.decrypt_master_key(master_password, encrypted_master_key)
        return self.post_decrypt_data(master_key)

    def get_encrypted_data(self, key, data):
        '''
        Combine some encryption methods in one call.

        :Arguments:
            key: bytes
            data: string or bytes string
        :Returns:
            bytes
        '''
        iv = self.get_iv()
        plain_data = self.pre_encrypt_data(data)
        encrypted_data = self.encrypt(key, iv, plain_data)
        post_encrypted_data = self.post_encrypt_data(encrypted_data)
        return post_encrypted_data

    def get_decrypted_data(self, key, encrypted_data):
        '''
        Combine some decryption methods in one call.

        :Arguments:
            key: bytes
            encrypted_data: bytes
        :Returns:
            bytes
        '''
        pre_decrypted_data = self.pre_decrypt_data(encrypted_data)
        decrypted_data = self.decrypt(key, pre_decrypted_data)
        post_decrypted_data = self.post_decrypt_data(decrypted_data)
        return post_decrypted_data

<<<<<<< HEAD


class FileCipher(Vault):

=======
>>>>>>> f2f76a7a9975cd97df706b73af01288b76a81db7
    def encrypt_file(self, master_password, file):
        '''
        Encrypt specified file.
        '''
        master_key = self.get_random_key()
        encrypted_master_key = self.encrypt_master_key(master_password, master_key)
        with open(file, 'rb') as in_file:
            data = in_file.read()
        data = self.pre_encrypt_data(data)
        iv = self.get_iv()
        encrypted_data = encrypted_master_key + self.encrypt(master_key, iv, data)
        out_file_name = file + '.encrypted'
        with open(out_file_name, 'wb') as out_file:
            out_file.write(encrypted_data)
        return None

    def decrypt_file(self, master_password, encrypted_file):
        '''
        Decrypt specified file.
        '''
        with open(encrypted_file, 'rb') as in_file:
            encrypted_data = in_file.read()
        encryped_master_key = encrypted_data[:112]
        encrypted_data = encrypted_data[112:]
        master_key = self.decrypt_master_key(master_password, encryped_master_key)
        decrypted_data = self.decrypt(master_key, encrypted_data)
        plain_data = self.post_decrypt_data(decrypted_data)
        # !!! Addition of suffix '.decrypted' should be removed !!!
        # !!! It'll be resulted in overwriting original file !!!
        # !!! In real case original file should be deleted after encryption
        # and this method will restore original file !!!
        out_file_name = encrypted_file.replace('encrypted', 'decrypted')
        with open(out_file_name, 'wb') as out_file:
            out_file.write(plain_data)
<<<<<<< HEAD
=======
        return None


# ==============================================================================
    def sign(self, key, msg):
        key = self.to_bytes(key)
        entry = self.to_bytes(msg)
        return hmac.new(key, msg, digestmod=self.HMAC_DIGESTMOD).hexdigest()

    def verify(self, key, msg, signature):
        key = self.to_bytes(key)
        entry = self.to_bytes(msg)
        digest = hmac.new(key, msg, digestmod=self.HMAC_DIGESTMOD).hexdigest()
        if digest != signature:
            raise Exception('Bad signature!')
>>>>>>> f2f76a7a9975cd97df706b73af01288b76a81db7
        return None
