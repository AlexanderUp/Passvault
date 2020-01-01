# encoding:utf-8
# Passvault module encryption tests

import Passvault
import unittest
import time
import os

from Cryptodome.Cipher import AES
from base64 import b16decode

from test_aux_function import make_average


ENC_KEY = b16decode('C3E70D3CA5A9E73668C1E685F4877FCF16EB39BBED97E9CC2DE182F8B7069BDB')
KDF_SALT = b16decode('A426668DFD750D3062BFA947F78C336F')
HMAC_SALT = b16decode('A426668DFD750D3062BFA947F78C336F')
IV = b16decode('FE7D7673787958BE864F355B9250CEB6')
PASSWORD = b'secret'
KEY = b16decode('31CB8EBE07CD7ACED6474DFA280BEB01')

PASSWORDS = ['secret', 'top secret', 'aaaaaaaa', '0000000000', '1w1w1w1w', '2294a191c4f234c0', 'aRRxqJ45zQo=', ' ', '.', 'p@s$VV0Rd']
PLAIN_TEXTS = ['Attack at down', 'attack at down', 'ATTACK AT DOWN', 'just another secret message', 'There is Tayler Darden?']
# test for byte data to be added

class PassvaultTest(unittest.TestCase):

    def setUp(self):
        self.vault = Passvault.Vault()
        self.another_vault = Passvault.Vault()
        self.iv = IV

    def test_get_random_key_human_readable(self, key=KEY):
        res = self.vault.get_random_key_human_readable(key)
        self.assertEqual(res, '31CB8EBE07CD7ACED6474DFA280BEB01')

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
        for key in (KEY, ENC_KEY):
            for test_text in PLAIN_TEXTS:
                plain_text = self.vault.pre_encrypt_data(test_text)
                encrypted_text = self.vault.encrypt(key, self.iv, plain_text)
                encrypted_text = self.vault.post_encrypt_data(encrypted_text)

                encrypted_text = self.vault.pre_decrypt_data(encrypted_text)
                decrypted_text = self.vault.decrypt(key, encrypted_text)
                decrypted_text = self.vault.post_decrypt_data(decrypted_text)
                self.assertEqual(test_text, decrypted_text.decode('utf-8'))

    def test_encryption_advanced(self):
        key = ENC_KEY
        self.assertNotEqual(id(self.vault), id(self.another_vault))
        for test_text in PLAIN_TEXTS:
            plain_text = self.vault.pre_encrypt_data(test_text)
            encrypted_text = self.vault.encrypt(key, self.iv, plain_text)
            encrypted_text = self.vault.post_encrypt_data(encrypted_text)

            encrypted_text = self.another_vault.pre_decrypt_data(encrypted_text)
            decrypted_text = self.another_vault.decrypt(key, encrypted_text)
            decrypted_text = self.another_vault.post_decrypt_data(decrypted_text)
            self.assertNotEqual(id(self.vault), id(self.another_vault))
            self.assertEqual(test_text, decrypted_text.decode('utf-8'))

    def test_master_key_encryption(self, password=PASSWORD, enc_key=ENC_KEY):
        pre_enc_key = self.vault.pre_encrypt_data(enc_key)
        encrypted_enc_key = self.vault.encrypt_enc_key(password, pre_enc_key)
        encrypted_enc_key = self.vault.post_encrypt_data(encrypted_enc_key)
        encrypted_enc_key = self.vault.pre_decrypt_data(encrypted_enc_key)
        decrypted_enc_key = self.vault.decrypt_enc_key(password, encrypted_enc_key)
        decrypted_enc_key = self.vault.post_decrypt_data(decrypted_enc_key)
        self.assertEqual(enc_key, decrypted_enc_key)

    def test_master_key_encryption_debugging(self, passwords=PASSWORDS, plain_texts=PLAIN_TEXTS):
        average = make_average()
        commencement_time = time.perf_counter()
        for password in passwords:
            for text in plain_texts:
                text = text.encode('utf-8')
                start_time = time.perf_counter()
                self.test_master_key_encryption(password, text)
                elapsed_time = time.perf_counter() - start_time
                average_time = average(elapsed_time)
        print('Total elapsed time: {}'.format(time.perf_counter() - commencement_time))
        print('Average time: {}'.format(average_time))
        print('Total rounds: {}'.format(len(passwords) * len(plain_texts)))

    def test_get_encrypted_decrypted_data(self):
        self.assertNotEqual(id(self.vault), id(self.another_vault))
        passwords = (os.urandom(self.vault.KEY_SIZE) for i in range(256))
        for password in passwords:
            for plain_text in PLAIN_TEXTS:
                encrypted_message = self.vault.get_encrypted_data(password, plain_text)
                decrypted_message = self.another_vault.get_decrypted_data(password, encrypted_message)
                self.assertEqual(plain_text, decrypted_message.decode('utf-8'))

    @unittest.skip
    def test_signature(self, key, entry):
        signature = self.vault.sign(key, entry)
        self.vault.verify(key, entry, signature)
        print('Key: {}, entry: {} PASSED'.format(key, entry))


if __name__ == '__main__':
    print('*' * 150)
    print('Tests running....')
    unittest.main()
