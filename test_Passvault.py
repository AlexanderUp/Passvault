# encoding:utf-8
# Tests for Passvault

import sys
import hashlib
import hmac
import time

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


print('=' * 75)

try:
    import Passvault
except ImportError:
    print('Can\'t load module Passvault')
    sys.exit()
else:
    print('Import succesfull!')


def test_encryption(key, plain_text):
    f = Passvault.Vault()
    encrypted_text = f.encrypt(key, IV, text)
    decrypted_text = f.decrypt(key, encrypted_text)
    return (encrypted_text, decrypted_text)

def test_master_key_encryption(password=PASSWORD, enc_key=ENC_KEY):
    f = Passvault.Vault()
    t = enc_key
    enc_key = f.pre_encrypt_data(enc_key)
    encrypted_enc_key = f.encrypt_enc_key(password, enc_key)
    encrypted_enc_key = f.post_encrypt_data(encrypted_enc_key)
    encrypted_enc_key = f.pre_decrypt_data(encrypted_enc_key)
    decrypted_enc_key = f.decrypt_enc_key(password, encrypted_enc_key)
    decrypted_enc_key = f.post_decrypt_data(decrypted_enc_key)
    assert t == decrypted_enc_key
    return (password, t, encrypted_enc_key, decrypted_enc_key)

def test_base64(message):
    f = Passvault.Vault()
    encoded = f.encode_base64(message)
    decoded = f.decode_base64(encoded)
    return message == decoded

def test_padding(plain_text):
    f = Passvault.Vault()
    print('plain_text: {}'.format(plain_text))
    plain_text = f.pre_encrypt_data(plain_text)
    print('pre_encrypt_data: {}'.format(plain_text))
    return f.post_decrypt_data(plain_text)

def test_master_key_encryption_debugging(passwords, plain_text):
    commencement_time = time.time()
    print('{} encryption mode used.'.format(ENCRYPTION_MODES[Passvault.Vault.AES_MODE]))
    for password_ in passwords:
        for text in plain_text:
            start_time = time.time()
            print('Password tested: {}'.format(password_))
            print('Plain text tested: {}'.format(text))
            r = test_master_key_encryption(password_, text)[2]
            print('Decrypted: {}'.format(r))
            print('Result: {}'.format(text == r))
            print('Elapsed time: {}'.format(time.time() - start_time))
    print('Total elapsed time: {}'.format(time.time() - commencement_time))

def test_signature(key, entry):
    f = Passvault.Vault()
    signature = f.sign(key, entry)
    f.verify(key, entry, signature)
    print('Key: {}, entry: {} PASSED'.format(key, entry))

if __name__ == '__main__':
    print('=' * 75)
    # functions = [test_encryption, test_master_key_encryption, test_base64, test_padding, test_master_key_encryption_debugging, test_signature]
    # passwords = ['secret', 'aRRxqJ45zQo=', 'p@s$VV0Rd']
    passwords = ['secret', 'top secret', 'aaaaaaaa', '0000000000', '1w1w1w1w', '2294a191c4f234c0', 'aRRxqJ45zQo=', ' ', '.', 'p@s$VV0Rd']
    plain_text = ['Attack at down', 'attack at down', 'ATTACK AT DOWN', 'just another secret message', 'There is Tayler Darden?']
    # test_master_key_encryption_debugging(passwords, plain_text)
    for password in passwords:
        for text in plain_text:
            # print('test encryption: password={}; key={}'.format(password, text))
            # print('returned: ')
            # test_encryption(password, text)
            print('test master key encryption: password={}; enc_key'.format(password, text))
            test_master_key_encryption(password=PASSWORD, enc_key=ENC_KEY)
            # print('test base64 encoding: text={}'.format(text))
            # test_base64(text)
            # print('test padding: text={}'.format(text))
            # test_padding(text)
            print('test master key encryption debugging: password={}; plain text={}'.format(password, text))
            test_master_key_encryption_debugging(password, text)
            # test_signature(password, text)
