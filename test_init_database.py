# encoding:utf-8
# tests for database initialization script


import unittest
from sqlalchemy import inspect

import database_model as dbm
from init_database import DBInitializer
from Passvault import Vault


PASSWORD = 'testtesttest'
REFERRENCE_TABLES_LIST = ['passwords', 'groups', 'vault']


class DBInitializerTest(unittest.TestCase):

    def setUp(self):
        self.path = ':memory:'
        self.master_password = 'testtesttest'
        self.db_initializer = DBInitializer(self.path)
        self.db_initializer.init_database(self.master_password)
        self.vault = Vault()

    def tearDown(self):
        pass

    def test_table_existence(self):
        inspector = inspect(self.db_initializer.engine)
        tables = inspector.get_table_names()
        self.assertSetEqual(set(tables), set(REFERRENCE_TABLES_LIST))

    def test_vault_atribute_existence(self):
        query = self.db_initializer.session.query(dbm.Vault)
        id_count = query.count()
        self.assertEqual(id_count, 1)
        row = query.first()
        self.assertIsNotNone(row.id)
        self.assertIsNotNone(row.vault_id)
        self.assertIsNotNone(row.encrypted_master_key)

    def test_master_key_decryption(self):
        query = self.db_initializer.session.query(dbm.Vault).first()
        encrypted_master_key = query.encrypted_master_key
        master_key = self.vault.get_master_key(self.master_password, encrypted_master_key)
        self.assertIsNotNone(master_key)


if __name__ == '__main__':
    unittest.main()
