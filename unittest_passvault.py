# encoding:utf-8
# unittest for Passvault module

# python3 -m unittest -v unittest_passvault.py

import unittest
import Passvault

# import test_data_from_Crypto

class VaultTest(unittest.TestCase):
    def test_padding(self):
        test = '00112233445566778899aabbccddeeff'
        t = Passvault.Vault()
        res = t.pre_encrypt_data(test)
        res = t.post_decrypt_data(res)
        res = t.to_str(res)
        self.assertEqual(res, test)

    # # current implementation of Passvault.Vault.verify() isn't support this test case
    # def test_signature(self):
    #     entry = '00112233445566778899aabbccddeeff'
    #     key = 'key' * 5
    #     t = Passvault.Vault()
    #     signature = t.sign(key, entry)
    #     digest = t.verify(key, entry, signature)
    #     self.assertEqual(digest, signature)

    def test_pre_post_func(self):
        plain_text = '00112233445566778899aabbccddeeff'
        t = Passvault.Vault()
        data = t.pre_encrypt_data(plain_text)
        data = t.post_encrypt_data(data)
        data = t.pre_decrypt_data(data)
        data = t.post_decrypt_data(data)
        data = t.to_str(data)
        self.assertEqual(plain_text, data)

    # encryption/decryption of enc_key is testing below...
    def test_encr_decr_enc_key_func(self):
        plain_text = '00112233445566778899aabbccddeeff'
        passwd = 'QWERTY'
        t = Passvault.Vault()
        data = t.pre_encrypt_data(plain_text)
        crypted = t.encrypt_enc_key(passwd, data)
        crypted = t.post_encrypt_data(crypted)
        crypted = t.pre_decrypt_data(crypted)
        decrypted = t.decrypt_enc_key(passwd, crypted)
        decrypted = t.post_decrypt_data(decrypted)
        decrypted = t.to_str(decrypted)
        self.assertEqual(plain_text, decrypted)

    # common encrypt/decrypt functions are testing below...
    def test_crypt_decrypt_func(self):
        plain_text = '00112233445566778899aabbccddeeff'
        iv = b'\x07\x83\x01\xdb\xfb\xd8\x93o\x14f\x18B*\xc4\x86\xee'
        key = '0' * 32
        t = Passvault.Vault()
        entry = t.pre_encrypt_data(plain_text)
        encrypted = t.encrypt(key, iv, entry)
        encrypted = t.post_encrypt_data(encrypted)
        encrypted = t.pre_decrypt_data(encrypted)
        decrypted = t.decrypt(key, encrypted)
        decrypted = t.post_decrypt_data(decrypted)
        decrypted = t.to_str(decrypted)
        self.assertEqual(plain_text, decrypted)

if __name__ == '__main__':
    unittest.main()
