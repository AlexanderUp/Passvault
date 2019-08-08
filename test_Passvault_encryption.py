# encoding:utf-8
# Passvault module encryption tests

import Passvault
import unittest
import time

from Crypto.Cipher import AES

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
        self.iv = IV

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
        key = ENC_KEY
        for test_text in PLAIN_TEXTS:
            plain_text = self.vault.pre_encrypt_data(test_text)
            encrypted_text = self.vault.encrypt(key, self.iv, plain_text)
            decrypted_text = self.vault.decrypt(key, encrypted_text)
            decrypted_text = self.vault.post_decrypt_data(decrypted_text)
            self.assertEqual(test_text, decrypted_text.decode('utf-8'))

    def test_master_key_encryption(self, password=PASSWORD, enc_key=ENC_KEY):
        pre_enc_key = self.vault.pre_encrypt_data(enc_key)
        encrypted_enc_key = self.vault.encrypt_enc_key(password, pre_enc_key)
        encrypted_enc_key = self.vault.post_encrypt_data(encrypted_enc_key)
        encrypted_enc_key = self.vault.pre_decrypt_data(encrypted_enc_key)
        decrypted_enc_key = self.vault.decrypt_enc_key(password, encrypted_enc_key)
        decrypted_enc_key = self.vault.post_decrypt_data(decrypted_enc_key)
        self.assertEqual(enc_key, decrypted_enc_key)

    def test_master_key_encryption_debugging(self, passwords=PASSWORDS, plain_text=PLAIN_TEXTS):
        commencement_time = time.perf_counter()
        print('{} encryption mode used.'.format(ENCRYPTION_MODES[Passvault.Vault.AES_MODE]))
        for password_ in passwords:
            for text in plain_text:
                text = text.encode('utf-8')
                print('Password tested: {}'.format(password_))
                print('Plain text tested: {}'.format(text))
                start_time = time.perf_counter()
                r = self.test_master_key_encryption(password_, text)
                print('Elapsed time: {}'.format(time.perf_counter() - start_time))
                print('Decrypted: {}'.format(r))
                # average time to be calculated
        print('Total elapsed time: {}'.format(time.perf_counter() - commencement_time))

    @unittest.skip
    def test_signature(self, key, entry):
        signature = self.vault.sign(key, entry)
        self.vault.verify(key, entry, signature)
        print('Key: {}, entry: {} PASSED'.format(key, entry))


if __name__ == '__main__':
    print('*' * 150)
    print('Tests running....')
    unittest.main()
