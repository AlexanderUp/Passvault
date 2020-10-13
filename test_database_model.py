# encoding:utf-8
# tests for database_model Passvault module

import unittest
import database_model as dbm

from sqlalchemy import create_engine
from sqlalchemy.orm import mapper
from sqlalchemy.orm import sessionmaker


mapper(dbm.Vault, dbm.table_vault)
mapper(dbm.Password, dbm.table_password)
mapper(dbm.Group, dbm.table_group)


class DatabaseModelTest(unittest.TestCase):

    def setUp(self):
        self.engine = create_engine('sqlite:///:memory:', echo=False)
        dbm.metadata.create_all(bind=self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def tearDown(self):
        self.session.rollback()
        self.session.close()
        for table in dbm.metadata.tables:
            dbm.metadata.tables[table].drop(self.engine)

    def test_insertion(self):
        v = dbm.Vault(vault_id=1,
                    encrypted_master_key='111111',
                    db_schema_version='1',
                    crypto_version='1',
                    passvault_app_version='1')
        p = dbm.Password(group_id=1,
                    account_name='test_account',
                    login='test_login',
                    url='url.com',
                    encrypted_password='secret',
                    memo='my memo')
        g = dbm.Group(group_name='test_group')
        self.session.add(v)
        self.session.add(p)
        self.session.add(g)
        self.session.commit()
        v_ = self.session.query(dbm.Vault).first()
        p_ = self.session.query(dbm.Password).first()
        g_ = self.session.query(dbm.Group).first()
        self.assertEqual(v, v_)
        self.assertEqual(p, p_)
        self.assertEqual(g, g_)

    def test_multiple_insertion(self):
        iteration_count = 100
        for i in range(iteration_count):
            p = dbm.Password(group_id=i%3,
                            account_name='test_account_{}'.format(i),
                            login='test_login_{}'.format(i),
                            url='url_{}.com'.format(i),
                            encrypted_password='secret_{}'.format(i),
                            memo='my memo')
            self.session.add(p)
        self.session.commit()
        count = self.session.query(dbm.Password).count()
        self.assertEqual(count, iteration_count)


if __name__ == '__main__':
    unittest.main()
