# encoding:utf-8
# AES encryption/decryption CBC mode Monte-Carlo tests

import unittest

from Crypto.Cipher import AES
from base64 import b16encode, b16decode
from aux_function_for_tests import pad_with_zeroes


class AES_CBC_MTC_Test(unittest.TestCase):

    def test_mtc_encryption_cbc128_first_loop(self):
        iv_initial = b16decode('00000000000000000000000000000000')
        key_initial = b16decode('00000000000000000000000000000000')
        plain_text_initial = b16decode('00000000000000000000000000000000')
        iv = iv_initial
        key = key_initial
        input_block = plain_text_initial
        for j in range(10000):
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(input_block)
            if j == 0:
                input_block = iv
            else:
                input_block = cipher_text_previous_iteration
            cipher_text_previous_iteration = cipher_text
            iv = cipher_text
        self.assertEqual(cipher_text, b16decode('8A05FC5E095AF4848A08D328D3688E3D'))

    def test_mtc_encryption_cbc128(self):
        '''Cipher Block Chaining (CBC) Mode - ENCRYPTION - Monte Carlo Test - 128 bits key'''
        key = b16decode('00000000000000000000000000000000')
        iv = b16decode('00000000000000000000000000000000')
        plain_text = b16decode('00000000000000000000000000000000')
        for i in range(400):
            for j in range(10000):
                cipher = AES.new(key, AES.MODE_CBC, iv)
                cipher_text = cipher.encrypt(plain_text)
                if j == 0:
                    plain_text = iv
                else:
                    plain_text = cipher_text_previous_iteration
                cipher_text_previous_iteration = cipher_text
                iv = cipher_text
            key = b16encode(key)
            cipher_text = b16encode(cipher_text)
            key = hex(int(key, 16) ^ int(cipher_text, 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key)
            key = b16decode(key)
            cipher_text = b16decode(cipher_text)
        self.assertEqual(cipher_text, b16decode('2F844CBF78EBA70DA7A49601388F1AB6'))

    def test_mtc_decryption_cbc128_first_loop(self):
        key = b16decode('00000000000000000000000000000000')
        iv = b16decode('00000000000000000000000000000000')
        cipher_text = b16decode('00000000000000000000000000000000')
        print()
        chaining_value = iv
        for j in range(10000):
            input_block = cipher_text
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plain_text = cipher.decrypt(input_block)
            plain_text = hex(int(b16encode(plain_text), 16) ^ int(b16encode(chaining_value), 16))
            plain_text = plain_text.upper().lstrip('0X')
            plain_text = pad_with_zeroes(plain_text)
            plain_text = b16decode(plain_text)
            chaining_value = cipher_text
            cipher_text = plain_text
        self.assertEqual(plain_text, b16decode('FACA37E0B0C85373DF706E73F7C9AF86'))

    def test_mtc_decryption_cbc128(self):
        '''Cipher Block Chaining (CBC) Mode - DECRYPTION - Monte Carlo Test - 128 bits key'''
        key = b16decode('00000000000000000000000000000000')
        iv = b16decode('00000000000000000000000000000000')
        cipher_text = b16decode('00000000000000000000000000000000')
        chaining_value = iv
        for i in range(400):
            for j in range(10000):
                input_block = cipher_text
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plain_text = cipher.decrypt(input_block)
                plain_text = hex(int(b16encode(plain_text), 16) ^ int(b16encode(chaining_value), 16))
                plain_text = plain_text.upper().lstrip('0X')
                plain_text = pad_with_zeroes(plain_text)
                plain_text = b16decode(plain_text)
                chaining_value = cipher_text
                cipher_text = plain_text
            key = hex(int(b16encode(key), 16) ^ int(b16encode(plain_text), 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key)
            key = b16decode(key)
        self.assertEqual(plain_text, b16decode('9B8FB71E035CEFF9CBFA1346E5ACEFE0'))

    def test_mtc_encryption_cbc192(self):
        '''Cipher Block Chaining (CBC) Mode - ENCRYPTION - Monte Carlo Test - 192 bits key'''
        key = b16decode('000000000000000000000000000000000000000000000000')
        iv = b16decode('00000000000000000000000000000000')
        plain_text = b16decode('00000000000000000000000000000000')
        for i in range(400):
            for j in range(10000):
                cipher = AES.new(key, AES.MODE_CBC, iv)
                cipher_text = cipher.encrypt(plain_text)
                if j == 0:
                    plain_text = iv
                else:
                    plain_text = cipher_text_previous_iteration
                if j == 9998:
                    cipher_text_for_key_expansion = cipher_text
                cipher_text_previous_iteration = cipher_text
                iv = cipher_text
            key = b16encode(key)
            cipher_text_expanded = b16encode(cipher_text_for_key_expansion[8:] + cipher_text)
            key = hex(int(key, 16) ^ int(cipher_text_expanded, 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key, 48)
            key = b16decode(key)
        self.assertEqual(cipher_text, b16decode('BA50C94440C04A8C0899D42658E25437'))

    def test_mtc_decryption_cbc192(self):
        '''Cipher Block Chaining (CBC) Mode - DECRYPTION - Monte Carlo Test - 192 bits key'''
        key = b16decode('000000000000000000000000000000000000000000000000')
        iv = b16decode('00000000000000000000000000000000')
        cipher_text = b16decode('00000000000000000000000000000000')
        chaining_value = iv
        for i in range(400):
            for j in range(10000):
                input_block = cipher_text
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plain_text = cipher.decrypt(input_block)
                plain_text = hex(int(b16encode(plain_text), 16) ^ int(b16encode(chaining_value), 16))
                plain_text = plain_text.upper().lstrip('0X')
                plain_text = pad_with_zeroes(plain_text)
                plain_text = b16decode(plain_text)
                chaining_value = cipher_text
                cipher_text = plain_text
                if j == 9998:
                    plain_text_previous_iteration = plain_text
            key = hex(int(b16encode(key), 16) ^ int(b16encode(plain_text_previous_iteration[8:] + plain_text), 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key, 48)
            key = b16decode(key)
        self.assertEqual(plain_text, b16decode('6342BFDDD2F6610350458B6695463484'))

    def test_mtc_encryption_cbc256(self):
        '''Cipher Block Chaining (CBC) Mode - ENCRYPTION - Monte Carlo Test - 256 bits key'''
        key = b16decode('0000000000000000000000000000000000000000000000000000000000000000')
        iv = b16decode('00000000000000000000000000000000')
        plain_text = b16decode('00000000000000000000000000000000')
        for i in range(400):
            for j in range(10000):
                cipher = AES.new(key, AES.MODE_CBC, iv)
                cipher_text = cipher.encrypt(plain_text)
                if j == 0:
                    plain_text = iv
                else:
                    plain_text = cipher_text_previous_iteration
                if j == 9998:
                    cipher_text_for_key_expansion = cipher_text
                cipher_text_previous_iteration = cipher_text
                iv = cipher_text
            key = b16encode(key)
            cipher_text_expanded = b16encode(cipher_text_for_key_expansion + cipher_text)
            key = hex(int(key, 16) ^ int(cipher_text_expanded, 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key, 64)
            key = b16decode(key)
        self.assertEqual(cipher_text, b16decode('C0FEFFF07506A0B4CD7B8B0CF25D3664'))

    def test_mtc_decryption_cbc256(self):
        '''Cipher Block Chaining (CBC) Mode - DECRYPTION - Monte Carlo Test - 256 bits key'''
        key = b16decode('0000000000000000000000000000000000000000000000000000000000000000')
        iv = b16decode('00000000000000000000000000000000')
        cipher_text = b16decode('00000000000000000000000000000000')
        chaining_value = iv
        for i in range(400):
            for j in range(10000):
                input_block = cipher_text
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plain_text = cipher.decrypt(input_block)
                plain_text = hex(int(b16encode(plain_text), 16) ^ int(b16encode(chaining_value), 16))
                plain_text = plain_text.upper().lstrip('0X')
                plain_text = pad_with_zeroes(plain_text)
                plain_text = b16decode(plain_text)
                chaining_value = cipher_text
                cipher_text = plain_text
                if j == 9998:
                    plain_text_previous_iteration = plain_text
            key = hex(int(b16encode(key), 16) ^ int(b16encode(plain_text_previous_iteration + plain_text), 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key, 64)
            key = b16decode(key)
        self.assertEqual(plain_text, b16decode('CD6429CF3F81F8B4F82BC627A8283096'))


if __name__ == '__main__':
    print('*' * 150)
    print('Tests running....')
    unittest.main()
