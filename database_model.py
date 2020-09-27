# encoding:utf-8
# passvault application database model


from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import DateTime


from datetime import datetime


metadata = MetaData()

table_vault = Table('vault', metadata,
                    Column('id', Integer, primary_key=True),
                    Column('vault_id', String, nullable=False),
                    Column('encrypted_enc_key', String, nullable=False, unique=True),
                    Column('created_on', DateTime, default=datetime.now),
                    Column('updated_on', DateTime, default=datetime.now, onupdate=datetime.now),
                    Column('db_schema_version', String, nullable=False),
                    Column('crypto_version', String, nullable=False),
                    Column('passvault_app_version', String, nullable=False))

table_password = Table('passwords', metadata,
                        Column('id', Integer, primary_key=True),
                        Column('group_id', Integer, index=True),
                        Column('account_name', String, nullable=False, unique=True, index=True),
                        Column('login', String, nullable=False, index=True),
                        Column('url', String, nullable=False, index=True),
                        Column('encrypted_password', String, nullable=False, unique=True),
                        Column('memo', String))

table_group = Table('groups', metadata,
                    Column('id', Integer, primary_key=True),
                    Column('group_name', String, nullable=False, unique=True))


class Vault():

    def __init__(self, vault_id, encrypted_enc_key, db_schema_version, \
                crypto_version, passvault_app_version):
        self.vault_id = vault_id
        self.encrypted_enc_key = encrypted_enc_key
        self.db_schema_version = db_schema_version
        self.crypto_version = crypto_version
        self.passvault_app_version = passvault_app_version

    def __repr__(self):
        return '<Vault id: {}>'.format(self.vault_id)


class Password():

    def __init__(self, group_id, account_name, login, url, encrypted_password, memo):
        self.group_id = group_id
        self.account_name = account_name
        self.login = login
        self.url = url
        self.encrypted_password = encrypted_password
        self.memo = memo

    def __repr__(self):
        return '<Password "{}">'.format(self.account_name)


class Group():

    def __init__(self, group_name):
        self.group_name = group_name

    def __repr__(self):
        return '<Group "{}">'.format(self.group_name)
