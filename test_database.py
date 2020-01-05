# encoding:utf-8
# tests for database module

# DON'T RUN THIS TESTS - TEST SQLITE3 DATABASE TO BE USED!!!

import database
import unittest

from base64 import b16decode

PASSWORD = b16decode('00112233445566778899AABBCCDDEEFF')
ENC_KEY = b16decode('00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF')

class DatabaseTest(unittest.TestCase):

    def setUp(self):
        self.database = database.Database()

    def tearDown(self):
        pass

    def test_init_encrypted_enc_key(self, password=PASSWORD, enc_key=ENC_KEY):
        enc_key_encrypted = self.database.init_encrypted_enc_key(password, enc_key) # enc_key encrypted by database_model returned
        enc_key_encrypted = self.database.pre_decrypt_data(enc_key_encrypted)
        self.assertIsInstance(enc_key_encrypted, bytes)
        enc_key_decrypted = self.database.decrypt_enc_key(password, enc_key_encrypted)
        enc_key_decrypted = self.database.post_decrypt_data(enc_key_decrypted)
        self.assertEqual(enc_key_decrypted, enc_key)

    @unittest.skip
    def test__init__(self):
        self.assertIsNone(self.database.conn)
        self.assertIsNone(self.database.cur)
        self.assertIsNone(self.enc_key)

    @unittest.skip
    def test_init_vault_id(self):
        self.assertIsInstance(self.database.init_vault_id(), str)

    # @unittest.skip
    # def test_connect_to_vault(self):
    #     conn, cur = self.database.connect_to_vault()
    #     self.assertIsNotNone(cur)
    #     self.assertIsNotNone(conn)
    #     cur.close()
    #     conn.close()
    #
    # @unittest.skip
    # def test_enc_key_decryption(self):
    #     conn, cur = self.database.connect_to_vault()
    #     enc_key = self.database.password_decrypt(conn, cur)
    #     self.assertIsNotNone(enc_key)
    #
    # @unittest.skip
    # def test_change_database_model(self):
    #     conn, cur = self.database.connect_to_vault()
    #     self.assertIsNone(self.database.change_password(conn, cur))
    #
    # @unittest.skip
    # def test_create_entry():
    #     conn, cur = self.database.connect_to_vault()
    #     enc_key = self.database.password_decrypt(conn, cur)
    #     self.assertIsNone(self.database.create_entry(conn, cur, enc_key))
    #
    # @unittest.skip
    # def test_get_entry_key():
    #     conn, cur = self.database.connect_to_vault()
    #     enc_key = self.database.password_decrypt(conn, cur)
    #     id_ = input('Enter entry id...\n>>> ')
    #     entry_key = self.database.get_entry_key(conn, cur, id_, enc_key)
    #     self.assertIsNotNone(entry_key)
    #
    # @unittest.skip
    # def test_update_entry():
    #     fields = ('group_id', 'account_name', 'login', 'url', 'memo')
    #     conn, cur = self.database.connect_to_vault()
    #     enc_key = self.database.password_decrypt(conn, cur)
    #     id_ = input('Entry id of entry to be updated...\n>>> ')
    #     print('Choose fields which you want to update....')
    #     data = {}
    #     for field in fields:
    #         answer = input('Do you want to update field "{}"? Y/N\n>>> '.format(field))
    #         if answer.lower() == 'y':
    #             data[field] = input('Input new value...\n>>> ')
    #         else:
    #             data[field] = None
    #     self.assertIsNone(self.database.update_entry(conn, cur, id_, enc_key, data))
    #
    # @unittest.skip
    # def test_delete_entry():
    #     conn, cur = self.database.connect_to_vault()
    #     id_ = input('Enter id of string to be deleted... \n>>> ')
    #     self.assertIsNone(self.database.delete_entry(conn, cur, id_))
    #
    # @unittest.skip
    # def test_get_list_of_entries():
    #     conn, cur = self.database.connect_to_vault()
    #     self.assertIsNone(self.database.get_list_of_entries(conn, cur))
    #
    # @unittest.skip
    # def test_update_database_model():
    #     conn, cur = self.database.connect_to_vault()
    #     self.assertIsNone(self.database.update_database_model(conn, cur, id_=3))
    #
    # @unittest.skip
    # def test_cleanup():
    #     conn, cur = self.database.connect_to_vault()
    #     self.assertIsNone(self.database.cleanup(conn, cur))


if __name__ == '__main__':
    print('*' * 150)
    print('Tests running....')
    # unittest.main()
