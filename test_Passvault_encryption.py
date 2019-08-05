# encoding:utf-8
# Passvault module encryption tests

import Passvault
import unittest
import test_data_from_Crypto
from Crypto.Cipher import AES
from test_data_from_Crypto import test_data
from base64 import b16encode, b16decode

# import sys
# import hashlib
# import hmac
# import time


# ===================== VARIABLES ==============================================
ENC_KEY = b'\xc3\xe7\r<\xa5\xa9\xe76h\xc1\xe6\x85\xf4\x87\x7f\xcf\x16\xeb9\xbb\xed\x97\xe9\xcc-\xe1\x82\xf8\xb7\x06\x9b\xdb'
KDF_SALT = b'\xa4&f\x8d\xfdu\r0b\xbf\xa9G\xf7\x8c3o'
HMAC_SALT = b'\xa4&f\x8d\xfdu\r0b\xbf\xa9G\xf7\x8c3o'
PASSWORD = b'secret'
IV = b'\xfe}vsxyX\xbe\x86O5[\x92P\xce\xb6'

ENCRYPTION_MODES = {
    1:'ECB',
    3:'CFB',
    2:'CBC',
    5:'OFB',
    6:'CTR',
}

PASSWORDS = ['secret', 'top secret', 'aaaaaaaa', '0000000000', '1w1w1w1w', '2294a191c4f234c0', 'aRRxqJ45zQo=', ' ', '.', 'p@s$VV0Rd']
PLAIN_TEXTS = ['Attack at down', 'attack at down', 'ATTACK AT DOWN', 'just another secret message', 'There is Tayler Darden?']
# ==============================================================================

class PassvaultTest(unittest.TestCase):

    def setUp(self):
        self.vault = Passvault.Vault()

    def pad_with_zeroes(self, key, key_lenght=32):
        if len(key) != key_lenght:
            key = '0' * (key_lenght - len(key)) + key
        return key

    def get_expanded_cipher_text(self, cipher_text, cipher_text_previous_iteration, key_length):
        if key_length == 48:
            return cipher_text_previous_iteration[32:] + cipher_text
        if key_lenght == 64:
            return cipher_text_previous_iteration + cipher_text
        return None

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
            key = self.pad_with_zeroes(key)
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
            key = self.pad_with_zeroes(key)
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
            key = self.pad_with_zeroes(key, 48)
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
            key = self.pad_with_zeroes(key, 48)
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
            key = self.pad_with_zeroes(key, 64)
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
            key = self.pad_with_zeroes(key, 64)
            key = b16decode(key)
            cipher_text = plain_text
        self.assertEqual(plain_text, plain_text_reference)

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
        key2_calculated = self.pad_with_zeroes(key2_calculated)
        key2_calculated = bytes.fromhex(key2_calculated)

        key3_calculated = hex(int(key2, 16) ^ int(cipher_text2, 16)).upper().lstrip('0X')
        key3_calculated = self.pad_with_zeroes(key3_calculated)
        key3_calculated = bytes.fromhex(key3_calculated)

        key4_calculated = hex(int(key3, 16) ^ int(cipher_text3, 16)).upper().lstrip('0X')
        key4_calculated = self.pad_with_zeroes(key4_calculated)
        key4_calculated = bytes.fromhex(key4_calculated)

        key7_calculated = hex(int(key6, 16) ^ int(cipher_text6, 16)).upper().lstrip('0X')
        key7_calculated = self.pad_with_zeroes(key7_calculated)
        key7_calculated = bytes.fromhex(key7_calculated)

        key8_calculated = hex(int(key7, 16) ^ int(cipher_text7, 16)).upper().lstrip('0X')
        key8_calculated = self.pad_with_zeroes(key8_calculated)
        key8_calculated = bytes.fromhex(key8_calculated)

        key128_calculated = hex(int(key127, 16) ^ int(cipher_text127, 16)).upper().lstrip('0X')
        key128_calculated = self.pad_with_zeroes(key128_calculated)
        key128_calculated = bytes.fromhex(key128_calculated)

        self.assertEqual(key2_calculated, bytes.fromhex(key2))
        self.assertEqual(key3_calculated, bytes.fromhex(key3))
        self.assertEqual(key4_calculated, bytes.fromhex(key4))
        self.assertEqual(key7_calculated, bytes.fromhex(key7))
        self.assertEqual(key8_calculated, bytes.fromhex(key8))
        self.assertEqual(key128_calculated, bytes.fromhex(key128))

    # @unittest.skip
    # def test_encryption(self):
    #     key = ENC_KEY
    #     for plain_text in PLAIN_TEXTS:
    #         encrypted_text = self.vault.encrypt(key, self.iv, plain_text.encode('utf-8'))
    #         decrypted_text = self.vault.decrypt(key, encrypted_text)
    #         self.assertEqual(plain_text, decrypted_text.decode('utf-8'))

    # @unittest.skip
    # def test_master_key_encryption(self, password=PASSWORD, enc_key=ENC_KEY):
    #     pre_enc_key = self.vault.pre_encrypt_data(enc_key)
    #     encrypted_enc_key = self.vault.encrypt_enc_key(password, pre_enc_key)
    #     encrypted_enc_key = self.vault.post_encrypt_data(encrypted_enc_key)
    #     encrypted_enc_key = self.vault.pre_decrypt_data(encrypted_enc_key)
    #     decrypted_enc_key = self.vault.decrypt_enc_key(password, encrypted_enc_key)
    #     decrypted_enc_key = self.vault.post_decrypt_data(decrypted_enc_key)
    #     self.assertEqual(enc_key, decrypted_enc_key)
    #
    # @unittest.skip
    # def test_master_key_encryption_debugging(self, passwords, plain_text):
    #     commencement_time = time.perf_counter()
    #     print('{} encryption mode used.'.format(ENCRYPTION_MODES[Passvault.Vault.AES_MODE]))
    #     for password_ in passwords:
    #         for text in plain_text:
    #             start_time = time.perf_counter()
    #             print('Password tested: {}'.format(password_))
    #             print('Plain text tested: {}'.format(text))
    #             r = test_master_key_encryption(password_, text)[2]
    #             print('Decrypted: {}'.format(r))
    #             print('Result: {}'.format(text == r))
    #             print('Elapsed time: {}'.format(time.perf_counter() - start_time))
    #     print('Total elapsed time: {}'.format(time.perf_counter() - commencement_time))
    #
    # @unittest.skip
    # def test_signature(self, key, entry):
    #     signature = self.vault.sign(key, entry)
    #     self.vault.verify(key, entry, signature)
    #     print('Key: {}, entry: {} PASSED'.format(key, entry))


if __name__ == '__main__':
    print('*' * 150)
    print('Tests running....')
    unittest.main()
