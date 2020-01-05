# encoding:utf-8

import os
import sqlalchemy as db

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

from datetime import datetime

# from config import Config
#
# engine = db.create_engine('sqlite:///' + Config['DIRECTORY'] + os.sep + Config['DATABASE_NAME'])

Base = declarative_base()

# ('CREATE table vault(id INTEGER PRIMARY KEY, vault_id NOT NULL, encrypted_enc_key NOT NULL)')
# ('CREATE table password(id INTEGER PRIMARY KEY, group_id NOT NULL, account_name NOT NULL, login, url, enc_password NOT NULL, memo TEXT)')
# ('CREATE table trashbin(id INTEGER PRIMARY KEY, previous_id INTEGER NOT NULL, group_id NOT NULL, account_name NOT NULL, login NOT NULL, url NOT NULL, enc_password NOT NULL, memo TEXT)')
# ('CREATE table groups(group_id INTEGER PRIMARY KEY, group_name NOT NULL)')
# ('INSERT INTO vault (vault_id, encrypted_enc_key) VALUES(?, ?)', (vault_id, encrypted_enc_key))

class Vault(Base):
    __tablename__ = 'vault'
    id = db.Column(db.Integer(), primary_key=True)
    vault_id = db.Column(db.Integer(), nullable=False)
    encrypted_enc_key = db.Column(db.String(192), nullable=False, unique=True)
    created_on = db.Column(db.DateTime(), default=datetime.now)
    updated_on = db.Column(db.DateTime(), default=datetime.now, onupdate=datetime.now)
    db_schema_version = db.Column(db.String(16), nullable=False)
    crypto_version = db.Column(db.String(16), nullable=False)
    passvault_app_version = db.Column(db.String(16), nullable=False)

    def __repr__(self):
        return '<Vault {} created on {}>'.format(self.vault_id, self.created_on)


class Password(Base):
    __tablename__ = 'passwords'
    id = db.Column(db.Integer(), primary_key=True)
    group_id = db.Column(db.Integer(), index=True)
    account_name = db.Column(db.String(256), nullable=False, unique=True, index=True)
    login = db.Column(db.String(256), nullable=False, index=True)
    url = db.Column(db.String(256), nullable=False, index=True)
    encrypted_password = db.Column(db.String(256), nullable=False, unique=True)
    memo = db.Column(db.String(1024))

    def __repr__(self):
        return '<Password {}>'.format(self.account_name)


class Group(Base):
    __tablename__ = 'groups'
    id = db.Column(db.Integer(), primary_key=True)
    group_name = db.Column(db.String(256), nullable=False, unique=True)
    # accounts = relationship('Password', secondary='passwords', backref='group')

    def __repr__(self):
        return '<Group {}>'.format(self.group_name)
