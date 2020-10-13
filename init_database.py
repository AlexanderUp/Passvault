# encoding:utf-8
# database initialization script


from sqlalchemy import create_engine
from sqlalchemy.orm import mapper
from sqlalchemy.orm import sessionmaker


import Passvault
import database_model as dbm


mapper(dbm.Vault, dbm.table_vault)
mapper(dbm.Password, dbm.table_password)
mapper(dbm.Group, dbm.table_group)


class DBInitializer():

    def __init__(self, path):
        self.engine = create_engine('sqlite:///' + path)
        dbm.metadata.create_all(bind=self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        self.vault = Passvault.Vault()

    def init_database(self, master_password):
        vault_id = self.vault.init_vault_id()
        master_key = self.vault.get_random_key()
        encrypted_master_key = self.vault.init_master_key(master_password, master_key)
        vault = dbm.Vault(vault_id=vault_id, encrypted_master_key=encrypted_master_key, \
                            db_schema_version='1.0.0', crypto_version='1.0.0', passvault_app_version='1.0.0')
        try:
            self.session.add(vault)
            self.session.commit()
        except Exception as err:
            print('Error occured')
            print(err)
            self.session.rollback()
        return None


if __name__ == '__main__':
    import os
    print('*' * 125)
    path = ':memory:'
    master_password = 'testtesttest'
    dbi = DBInitializer(path)
    dbi.init_database(master_password)
    query = dbi.session.query(dbm.Vault)
    print('query', query, sep=': ')
    vault_id_count = query.count()
    vault_id = query.first()
    print('vault_id_count', vault_id_count, sep=': ')
    print('vault_id', vault_id, sep=': ')
    vault_all = query.all()
    print('vault_all', vault_all, sep=': ')
    print(type(vault_id))
