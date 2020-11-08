# encoding: utf-8
# file cipher

import os


from Passvault import Vault


FILE = 'text.txt'
MASTER_PASSWORD = b'testtesttesttest'

PATH_PLAIN_FILE = os.path.join(os.getcwd(), FILE)
PATH_ENCRYPTED_FILE = os.path.join(os.getcwd(), FILE + '.encrypted')


if __name__ == '__main__':
    print('*' * 125)
    vault = Vault()

    with open(PATH_PLAIN_FILE, 'r') as ifile:
        data = ifile.read()
    print('Plain data:', data, sep='\n')

    enc_data = vault.get_encrypted_data(MASTER_PASSWORD, data)
    print(f'Encrypted data:\n{enc_data}\n')

    decr_data = vault.get_decrypted_data(MASTER_PASSWORD, enc_data)
    print(f'Decrypted data:\n{decr_data.decode("utf-8")}')


    vault.encrypt_file(MASTER_PASSWORD, PATH_PLAIN_FILE)
    print('File encrypted!')

    vault.decrypt_file(MASTER_PASSWORD, PATH_ENCRYPTED_FILE)
    print('File decrypted!')

    print('***** Done! *****')
