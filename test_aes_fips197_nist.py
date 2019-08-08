# encoding:utf-8
# AES ECB/CBC mode encryption/decryption fips 197 & NIST tests

import unittest

from Crypto.Cipher import AES
from base64 import b16encode, b16decode
from test_data_from_Crypto import test_data


class AES_fips_nist_test(unittest.TestCase):

    def test_fips_197(self):
        for (plain_text, cipher_text_reference, key, comment) in test_data[:3]:
            plain_text = b16decode(plain_text.upper())
            cipher_text_reference = b16decode(cipher_text_reference.upper())
            key = b16decode(key.upper())
            cipher = AES.new(key, AES.MODE_ECB)
            cipher_text = cipher.encrypt(plain_text)
            decipher = AES.new(key, AES.MODE_ECB)
            decrypted_text = decipher.decrypt(cipher_text)
            self.assertNotEqual(id(cipher), id(decipher))
            self.assertEqual(cipher_text, cipher_text_reference)
            self.assertEqual(decrypted_text, plain_text)

    def test_nist_800_38a_encryption_ecb(self):
        for (plain_text, cipher_text_reference, key, comment) in test_data[387:390]:
            plain_text = b16decode(plain_text.upper())
            cipher_text_reference = b16decode(cipher_text_reference.upper())
            key = b16decode(key.upper())
            cipher = AES.new(key, AES.MODE_ECB)
            cipher_text = cipher.encrypt(plain_text)
            self.assertEqual(cipher_text, cipher_text_reference)

    def test_nist_800_38a_encryption_cbc(self):
        for (plain_text, cipher_text_reference, key, comment, dict_) in test_data[390:393]:
            plain_text = b16decode(plain_text.upper())
            cipher_text_reference = b16decode(cipher_text_reference.upper())
            key = b16decode(key.upper())
            iv = b16decode(dict_['iv'].upper())
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(plain_text)
            self.assertEqual(cipher_text, cipher_text_reference)

    def test_nist_800_38a_decryption_ecb(self):
        for (plain_text_reference, cipher_text, key, comment) in test_data[387:390]:
            plain_text_reference = b16decode(plain_text_reference.upper())
            cipher_text = b16decode(cipher_text.upper())
            key = b16decode(key.upper())
            cipher = AES.new(key, AES.MODE_ECB)
            plain_text = cipher.decrypt(cipher_text)
            self.assertEqual(plain_text, plain_text_reference)

    def test_nist_800_38a_decryption_cbc(self):
        for (plain_text_reference, cipher_text, key, comment, dict_) in test_data[390:393]:
            plain_text_reference = b16decode(plain_text_reference.upper())
            cipher_text = b16decode(cipher_text.upper())
            key = b16decode(key.upper())
            iv = b16decode(dict_['iv'].upper())
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plain_text = cipher.decrypt(cipher_text)
            self.assertEqual(plain_text, plain_text_reference)

if __name__ == '__main__':
    print('*' * 150)
    print('Tests running....')
    unittest.main()
