# encoding:utf-8

# tests for database_model Passvault module

import unittest
import database_model as db

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from random import randint as r


class DatabaseModelTest(unittest.TestCase):

    def setUp(self):
        engine = create_engine('sqlite:///:memory:', echo=False)
        db.Base.metadata.create_all(bind=engine)
        Session = sessionmaker(bind=engine)
        self.session = Session()

    def tearDown(self):
        self.session.rollback()
        self.session.close()

    def test_insertion(self):
        v = db.Vault(vault_id=1, encrypted_enc_key='111111', db_schema_version='1', \
                    crypto_version='1', passvault_app_version='1')
        p = db.Password(group_id=1, account_name='test_account', login='test_login', \
                    url='url.com', encrypted_password='secret', memo='my memo')
        g = db.Group(group_name='test_group')
        self.session.add(v)
        self.session.add(p)
        self.session.add(g)
        self.session.commit()
        v_ = self.session.query(db.Vault).first()
        p_ = self.session.query(db.Password).first()
        g_ = self.session.query(db.Group).first()
        self.assertEqual(v, v_)
        self.assertEqual(p, p_)
        self.assertEqual(g, g_)

    def test_multiple_insertion(self):
        iteration_count = 100
        for i in range(iteration_count):
            p = db.Password(group_id=r(1, 3), account_name='test_account_{}'.format(i), login='test_login_{}'.format(i), \
                        url='url_{}.com'.format(r(1, 100)), encrypted_password='secret_{}'.format(i), memo='my memo')
            self.session.add(p)
        self.session.commit()
        count = self.session.query(db.Password).count()
        self.assertEqual(count, iteration_count)


if __name__ == '__main__':
    unittest.main()
