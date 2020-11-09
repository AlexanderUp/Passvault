# encoding:utf-8
# AES encryption/decryption ECB mode Monte-Carlo tests

import unittest

from Cryptodome.Cipher import AES
from base64 import b16encode, b16decode
from aux import pad_with_zeroes


class AES_ECB_MTC_Test(unittest.TestCase):

    def test_hex_xor_128_bit(self):
        key1 = '00000000000000000000000000000000'
        cipher_text1 = 'C34C052CC0DA8D73451AFE5F03BE297F'

        key2 = 'C34C052CC0DA8D73451AFE5F03BE297F'
        cipher_text2 = '0AC15A9AFBB24D54AD99E987208272E2'

        key3 = 'C98D5FB63B68C027E88317D8233C5B9D'
        cipher_text3 = 'A3D43BFFA65D0E80092F67A314857870'

        key4 = '6A5964499D35CEA7E1AC707B37B923ED'

        key6 = '9591F146C6FF55F71138F822AEC4182D'
        cipher_text6 = '9B27361DBC8E5618E8E98036F5AD40B0'

        key7 = '0EB6C75B7A7103EFF9D178145B69589D'
        cipher_text7 = '21D9BD7EBA0163A293F2D56C316CBD36'

        key8 = '2F6F7A25C070604D6A23AD786A05E5AB'

        key127 = 'C53F8E6833A81B19DAF66BF9F1314474'

        cipher_text127 = 'C5B3D7089173958B32340B88D35B738B'
        key128 = '008C5960A2DB8E92E8C26071226A37FF'

        key2_calculated = hex(int(key1, 16) ^ int(cipher_text1, 16)).upper().lstrip('0X')
        key2_calculated = pad_with_zeroes(key2_calculated)
        key2_calculated = bytes.fromhex(key2_calculated)

        key3_calculated = hex(int(key2, 16) ^ int(cipher_text2, 16)).upper().lstrip('0X')
        key3_calculated = pad_with_zeroes(key3_calculated)
        key3_calculated = bytes.fromhex(key3_calculated)

        key4_calculated = hex(int(key3, 16) ^ int(cipher_text3, 16)).upper().lstrip('0X')
        key4_calculated = pad_with_zeroes(key4_calculated)
        key4_calculated = bytes.fromhex(key4_calculated)

        key7_calculated = hex(int(key6, 16) ^ int(cipher_text6, 16)).upper().lstrip('0X')
        key7_calculated = pad_with_zeroes(key7_calculated)
        key7_calculated = bytes.fromhex(key7_calculated)

        key8_calculated = hex(int(key7, 16) ^ int(cipher_text7, 16)).upper().lstrip('0X')
        key8_calculated = pad_with_zeroes(key8_calculated)
        key8_calculated = bytes.fromhex(key8_calculated)

        key128_calculated = hex(int(key127, 16) ^ int(cipher_text127, 16)).upper().lstrip('0X')
        key128_calculated = pad_with_zeroes(key128_calculated)
        key128_calculated = bytes.fromhex(key128_calculated)

        self.assertEqual(key2_calculated, bytes.fromhex(key2))
        self.assertEqual(key3_calculated, bytes.fromhex(key3))
        self.assertEqual(key4_calculated, bytes.fromhex(key4))
        self.assertEqual(key7_calculated, bytes.fromhex(key7))
        self.assertEqual(key8_calculated, bytes.fromhex(key8))
        self.assertEqual(key128_calculated, bytes.fromhex(key128))

    def test_mtc_encryption_ecb128_first_loop(self):
        key = b16decode('00000000000000000000000000000000')
        plain_text = b16decode('00000000000000000000000000000000')
        cipher = AES.new(key, AES.MODE_ECB)
        input_block = plain_text
        for j in range(10000):
            plain_text_inner = input_block
            cipher_text = cipher.encrypt(plain_text_inner)
            input_block = cipher_text
        self.assertEqual(cipher_text, b16decode('C34C052CC0DA8D73451AFE5F03BE297F'))

    def test_mtc_encryption_ecb192_first_loop(self):
        key = b16decode('000000000000000000000000000000000000000000000000')
        plain_text = b16decode('00000000000000000000000000000000')
        cipher = AES.new(key, AES.MODE_ECB)
        input_block = plain_text
        for j in range(10000):
            plain_text_inner = input_block
            cipher_text = cipher.encrypt(plain_text_inner)
            input_block = cipher_text
        self.assertEqual(cipher_text, b16decode('F3F6752AE8D7831138F041560631B114'))

    def test_mtc_encryption_ecb256_first_loop(self):
        key = b16decode('0000000000000000000000000000000000000000000000000000000000000000')
        plain_text = b16decode('00000000000000000000000000000000')
        cipher = AES.new(key, AES.MODE_ECB)
        input_block = plain_text
        for j in range(10000):
            plain_text_inner = input_block
            cipher_text = cipher.encrypt(plain_text_inner)
            input_block = cipher_text
        self.assertEqual(cipher_text, b16decode('8B79EECC93A0EE5DFF30B4EA21636DA4'))

    def test_mtc_encryption_ecb128(self):
        '''Electronic Codebook (ECB) Mode - ENCRYPTION - Monte Carlo Test - 128 bits key'''
        key = b16decode('00000000000000000000000000000000')
        plain_text = b16decode('00000000000000000000000000000000')
        cipher_text_reference = b16decode('A04377ABE259B0D0B5BA2D40A501971B')
        print()
        for i in range(400):
            cipher = AES.new(key, AES.MODE_ECB)
            input_block = plain_text
            for j in range(10000):
                plain_text_inner = input_block
                cipher_text = cipher.encrypt(plain_text_inner)
                input_block = cipher_text
            key = b16encode(key)
            cipher_text = b16encode(cipher_text)
            key = hex(int(key, 16) ^ int(cipher_text, 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key)
            key = b16decode(key)
            plain_text = b16decode(cipher_text)
        self.assertEqual(b16decode(cipher_text), cipher_text_reference)

    def test_mtc_decryption_ecb128(self):
        '''Electronic Codebook (ECB) Mode - DECRYPTION - Monte Carlo Test - 128 bits key'''
        key = b16decode('00000000000000000000000000000000')
        cipher_text = b16decode('00000000000000000000000000000000')
        plain_text_reference = b16decode('F5BF8B37136F2E1F6BEC6F572021E3BA')
        print()
        for i in range(400):
            cipher = AES.new(key, AES.MODE_ECB)
            input_block = cipher_text
            for j in range(10000):
                cipher_text_inner = input_block
                plain_text = cipher.decrypt(cipher_text_inner)
                input_block = plain_text
            key = b16encode(key)
            plain_text = b16encode(plain_text)
            key = hex(int(key, 16) ^ int(plain_text, 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key)
            key = b16decode(key)
            cipher_text = b16decode(plain_text)
        self.assertEqual(b16decode(plain_text), plain_text_reference)

    def test_mtc_encryption_ecb192(self):
        '''Electronic Codebook (ECB) Mode - ENCRYPTION - Monte Carlo Test - 192 bits key'''
        key = b16decode('000000000000000000000000000000000000000000000000')
        plain_text = b16decode('00000000000000000000000000000000')
        cipher_text_reference = b16decode('4E46F8C5092B29E29A971A0CD1F610FB')
        print()
        for i in range(400):
            cipher = AES.new(key, AES.MODE_ECB)
            input_block = plain_text
            for j in range(10000):
                plain_text_inner = input_block
                cipher_text = cipher.encrypt(plain_text_inner)
                if j == 9998:
                    cipher_text_previous_iteration = cipher_text
                input_block = cipher_text
            key = b16encode(key)
            cipher_text_expanded = b16encode(cipher_text_previous_iteration[8:] + cipher_text)
            key = hex(int(key, 16) ^ int(cipher_text_expanded, 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key, 48)
            key = b16decode(key)
            plain_text = cipher_text
        self.assertEqual(cipher_text, cipher_text_reference)

    def test_mtc_decryption_ecb192(self):
        '''Electronic Codebook (ECB) Mode - DECRYPTION - Monte Carlo Test - 192 bits key'''
        key = b16decode('000000000000000000000000000000000000000000000000')
        cipher_text = b16decode('00000000000000000000000000000000')
        plain_text_reference = b16decode('F1A81B68F6E5A6271A8CB24E7D9491EF')
        print()
        for i in range(400):
            cipher = AES.new(key, AES.MODE_ECB)
            input_block = cipher_text
            for j in range(10000):
                cipher_text_inner = input_block
                plain_text = cipher.decrypt(cipher_text_inner)
                if j == 9998:
                    plain_text_previous_iteration = plain_text
                input_block = plain_text
            key = b16encode(key)
            plain_text_expanded = b16encode(plain_text_previous_iteration[8:] + plain_text)
            key = hex(int(key, 16) ^ int(plain_text_expanded, 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key, 48)
            key = b16decode(key)
            cipher_text = plain_text
        self.assertEqual(plain_text, plain_text_reference)

    def test_mtc_encryption_ecb256(self):
        '''Electronic Codebook (ECB) Mode - ENCRYPTION - Monte Carlo Test - 256 bits key'''
        key = b16decode('0000000000000000000000000000000000000000000000000000000000000000')
        plain_text = b16decode('00000000000000000000000000000000')
        cipher_text_reference = b16decode('1F6763DF807A7E70960D4CD3118E601A')
        print()
        for i in range(400):
            cipher = AES.new(key, AES.MODE_ECB)
            input_block = plain_text
            for j in range(10000):
                plain_text_inner = input_block
                cipher_text = cipher.encrypt(plain_text_inner)
                if j == 9998:
                    cipher_text_previous_iteration = cipher_text
                input_block = cipher_text
            key = b16encode(key)
            cipher_text_expanded = b16encode(cipher_text_previous_iteration + cipher_text)
            key = hex(int(key, 16) ^ int(cipher_text_expanded, 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key, 64)
            key = b16decode(key)
            plain_text = cipher_text
        self.assertEqual(cipher_text, cipher_text_reference)

    def test_mtc_decryption_ecb256(self):
        '''Electronic Codebook (ECB) Mode - DECRYPTION - Monte Carlo Test - 256 bits key'''
        key = b16decode('0000000000000000000000000000000000000000000000000000000000000000')
        cipher_text = b16decode('00000000000000000000000000000000')
        plain_text_reference = b16decode('4DE0C6DF7CB1697284604D60271BC59A')
        print()
        for i in range(400):
            cipher = AES.new(key, AES.MODE_ECB)
            input_block = cipher_text
            for j in range(10000):
                cipher_text_inner = input_block
                plain_text = cipher.decrypt(cipher_text_inner)
                if j == 9998:
                    plain_text_previous_iteration = plain_text
                input_block = plain_text
            key = b16encode(key)
            plain_text_expanded = b16encode(plain_text_previous_iteration + plain_text)
            key = hex(int(key, 16) ^ int(plain_text_expanded, 16))
            key = key.upper().lstrip('0X')
            key = pad_with_zeroes(key, 64)
            key = b16decode(key)
            cipher_text = plain_text
        self.assertEqual(plain_text, plain_text_reference)

if __name__ == '__main__':
    print('*' * 150)
    print('Tests running....')
    unittest.main()
