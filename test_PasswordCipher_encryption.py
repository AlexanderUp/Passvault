# encoding:utf-8
# tests for PasswordCipher class


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
        self.vault = Passvault.PasswordCipher()
        self.another_vault = Passvault.PasswordCipher()
        self.iv = b16decode(IV)

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


if __name__ == '__main__':
    unittest.main()
