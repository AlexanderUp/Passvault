# encoding:utf-8
# Passvault module encryption tests

import Passvault
import unittest
import os

from base64 import b16decode

from test_data_Passvault_encryption import IV
from test_data_Passvault_encryption import KEYS
from test_data_Passvault_encryption import PASSWORDS
from test_data_Passvault_encryption import PLAIN_TEXTS


class PassvaultTest(unittest.TestCase):

    def setUp(self):
        self.vault = Passvault.Vault()
        self.another_vault = Passvault.Vault()
        self.iv = b16decode(IV)

    def test_get_random_key_human_readable(self):
        for key in KEYS:
            key_ = b16decode(key)
            res = self.vault.get_random_key_human_readable(key_)
            self.assertEqual(res, key)

    def test_base64(self):
        for plain_text in PLAIN_TEXTS:
            encoded = self.vault.encode_base64(plain_text.encode('utf-8'))
            decoded = self.vault.decode_base64(encoded)
            self.assertEqual(plain_text, decoded.decode('utf-8'))

    def test_padding(self):
        for plain_text in PLAIN_TEXTS:
            plain_text = plain_text.encode('utf-8')
            plain_text_padded = self.vault.pre_encrypt_data(plain_text)
            plain_text_depadded = self.vault.post_decrypt_data(plain_text_padded)
            self.assertEqual(plain_text, plain_text_depadded)

    def test_encryption(self):
        for key in KEYS:
            key = b16decode(key)
            for test_text in PLAIN_TEXTS:
                plain_text = self.vault.pre_encrypt_data(test_text)
                encrypted_text = self.vault.encrypt(key, self.iv, plain_text)
                encrypted_text = self.vault.post_encrypt_data(encrypted_text)

                encrypted_text = self.vault.pre_decrypt_data(encrypted_text)
                decrypted_text = self.vault.decrypt(key, encrypted_text)
                decrypted_text = self.vault.post_decrypt_data(decrypted_text)
                self.assertEqual(test_text, decrypted_text.decode('utf-8'))

    def test_encryption_advanced(self):
        self.assertNotEqual(id(self.vault), id(self.another_vault))
        for key in KEYS:
            key = b16decode(key)
            for test_text in PLAIN_TEXTS:
                plain_text = self.vault.pre_encrypt_data(test_text)
                encrypted_text = self.vault.encrypt(key, self.iv, plain_text)
                encrypted_text = self.vault.post_encrypt_data(encrypted_text)

                encrypted_text = self.another_vault.pre_decrypt_data(encrypted_text)
                decrypted_text = self.another_vault.decrypt(key, encrypted_text)
                decrypted_text = self.another_vault.post_decrypt_data(decrypted_text)
                self.assertEqual(test_text, decrypted_text.decode('utf-8'))

    def test_master_key_encryption(self):
        for master_key in KEYS:
            master_key = b16decode(master_key)
            for master_password in PASSWORDS:
                pre_master_key = self.vault.pre_encrypt_data(master_key)
                encrypted_master_key = self.vault.encrypt_master_key(master_password, pre_master_key)
                encrypted_master_key = self.vault.post_encrypt_data(encrypted_master_key)

                encrypted_master_key = self.vault.pre_decrypt_data(encrypted_master_key)
                decrypted_master_key = self.vault.decrypt_master_key(master_password, encrypted_master_key)
                decrypted_master_key = self.vault.post_decrypt_data(decrypted_master_key)
                self.assertEqual(master_key, decrypted_master_key)

<<<<<<< HEAD
=======
    def test_master_key_encryption_short(self):
        for key in KEYS:
            master_key = b16decode(key)
            for master_password in PASSWORDS:
                master_key_encrypted = self.vault.init_master_key(master_password, master_key)
                master_key_decrypted = self.vault.get_master_key(master_password, master_key_encrypted)
                self.assertEqual(master_key_decrypted, master_key)

    def test_get_encrypted_decrypted_data(self):
        self.assertNotEqual(id(self.vault), id(self.another_vault))
        passwords = (os.urandom(self.vault.KEY_SIZE) for i in range(512))
        for master_password in passwords:
            for plain_text in PLAIN_TEXTS:
                encrypted_message = self.vault.get_encrypted_data(master_password, plain_text)
                decrypted_message = self.another_vault.get_decrypted_data(master_password, encrypted_message)
                self.assertEqual(plain_text, decrypted_message.decode('utf-8'))

>>>>>>> f2f76a7a9975cd97df706b73af01288b76a81db7

if __name__ == '__main__':
    unittest.main()
