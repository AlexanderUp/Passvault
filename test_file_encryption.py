# encoding:utf-8
# tests for file encryption by Passvault


import unittest
import hashlib
import os

import Passvault
import config
import aux


class FileCryptorTest(unittest.TestCase):

    def setUp(self):
        conf = config.FileCryptorTestConfig()
        self.vault = Passvault.FileCipher()
        self.master_password = conf.MASTER_PASSWORD
        self.plain_file_path = conf.PLAIN_FILE
        self.encrypted_file_path = conf.PLAIN_FILE + '.encrypted'
        self.plain_file_hash = aux.get_hash(self.plain_file_path)

    def tearDown(self):
        pass

    def test_file_encryption(self):
        self.vault.encrypt_file(self.master_password, self.plain_file_path)
        self.vault.decrypt_file(self.master_password, self.encrypted_file_path)
        decrypted_file_hash = aux.get_hash(self.encrypted_file_path.replace('encrypted', 'decrypted'))
        self.assertEqual(self.plain_file_hash, decrypted_file_hash)

    @unittest.skip
    def test_different_passwords(self):
        for i in range(25):
            master_password = os.urandom(128)
            self.vault.encrypt_file(master_password, self.plain_file_path)
            self.vault.decrypt_file(master_password, self.encrypted_file_path)
            decrypted_file_hash = aux.get_hash(self.encrypted_file_path.replace('encrypted', 'decrypted'))
            self.assertEqual(self.plain_file_hash, decrypted_file_hash)


if __name__ == '__main__':
    unittest.main()
