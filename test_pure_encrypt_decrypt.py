# encoding:utf-8
# unittest for Passvault

import unittest
import sys

from Crypto.Cipher import AES

try:
    import Passvault
    from test_data_from_Crypto import test_data
except ImportError as err:
    print('Can\'t import some modules. Exiting...')
    sys.exit()
else:
    print('Import successfull!')


# >>> from Crypto.Cipher import AES
# >>> b = bytes('0', 'latin-1')
# >>> iv = b * AES.block_size
# >>> plaintext = '00112233445566778899aabbccddeeff'.encode('latin-1')
# >>> key = '000102030405060708090a0b0c0d0e0f'.encode('latin-1')
# >>> cipher = AES.new(key, AES.MODE_ECB, iv)

class PassvaultTest(unittest.TestCase):

    def setUp(self):
        self.vault = Passvault.Vault()

    def test_encryption(self):
        iv = bytes('0', 'latin-1') * AES.block_size
        for data in test_data[:3]:
            print('Testing...')
            key = data[2].encode('latin-1')
            plain_text = data[0].encode('latin-1')
            cipher_text = data[1].encode('latin-1')
            # key = bytes(data[2], encoding='utf-8')
            # plain_text = bytes(data[0], encoding='utf-8')
            # cipher_text = bytes(data[1], encoding='utf-8')
            print('Plain_text: {}'.format(plain_text))
            print('Cipher_text: {}'.format(cipher_text))
            print('Key: {}'.format(key))
            print('iv: {}'.format(iv))
            # self.assertEqual(self.vault.encrypt(key, iv, plain_text), bytes(cipher_text, encoding='utf-8'))
            self.assertEqual(self.vault.encrypt(key, iv, plain_text)[AES.block_size:], cipher_text)



if __name__ == '__main__':
    unittest.main()
