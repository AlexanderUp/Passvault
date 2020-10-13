# encoding:utf-8
# Class represents password database

'''
Each entry should be encrypted with randomly generated key,
which should be encrypted with master key and stored in password database.

master_password - user master_password used in PBKDF2 for master_key encription/decryption.

TO DO:

Every entry initializes with randomly generated password, salt and iv.
Every entry authenticated with hmac - sha3_256.
Every entry stores hmac digest in separate field.
'''


import os
import sys
import sqlalchemy
import Passvault
import database_model as dbm

from collections import namedtuple
from sqlalchemy import create_engine
from sqlalchemy.orm import mapper
from sqlalchemy.orm import sessionmaker


Entry = namedtuple('Entry', 'account_name login url group_id memo')


mapper(dbm.Vault, dbm.table_vault)
mapper(dbm.Password, dbm.table_password)
mapper(dbm.Group, dbm.table_group)


class Database():

	def __init__(self, master_password, path):
		self.vault = Passvault.Vault()
		self.master_password = master_password
		self.path = path
		self.engine = create_engine('sqlite:///' + self.path)
		Session = sessionmaker(bind=self.engine)
		self.session = Session()
		self.master_key = self.decrypt_master_key()

	def decrypt_master_key(self):
		'''
		Read and decrypt master_key stored in database (table vault).
		'''
		master_key_object = self.session.query(dbm.Vault).first()
		encrypted_master_key = master_key_object.encrypted_master_key
		master_key = self.vault.get_master_key(self.master_password, encrypted_master_key)
		return master_key

	def change_master_password(self, new_master_password):
		'''
		Decrypt master_key and encrypt it back using new master_password.
		'''

		try:
			vault_object = self.session.query(dbm.Vault).first()
		except sqlalchemy.exc.SQLAlchemyError as err:
			print(err)
		else:
			print(vault_object)

		new_encrypted_master_key = self.vault.init_master_key(new_master_password, self.master_key)

		try:
			vault_object.encrypted_master_key = new_encrypted_master_key
			self.session.commit()
		except sqlalchemy.exc.SQLAlchemyError as err:
			print(err)
			self.session.rollback()
		else:
			new_vault_object = self.session.query(dbm.Vault).first()
			print(f'New encrypted_master_key: {new_vault_object.encrypted_master_key}')
			self.master_password = new_master_password
			print(f'Master password changed! New: {self.master_password}')
		return None

	# TODO
	def update_password(self, id):
		'''
		Update password in entry.
		'''
		try:
			entry = self.session.query(dbm.Password).filter(dbm.Password.id==id).first()
		except sqlalchemy.orm.exc.NoResultFound as err:
			print('***** Database related error occured! *****')
			print(err)
		try:
			entry.encrypted_password = self.set_encrypted_password()
			self.session.commit()
		except sqlalchemy.exc.IntegrityError as err:
			print('***** IntegrityError error occured! *****')
			print(err)
			self.session.rollback()
		except sqlalchemy.exc.SQLAlchemyError as err:
			print('***** General SQLAlchemy Error occured! *****')
			print(err)
			self.session.rollback()
		else:
			print('Success! Password updated!')
		pass

	def edit_entry(self):
		'''
		Edit database entry.
		'''
		pass

	def set_encrypted_password(self):
		password = self.vault.get_random_key()
		encrypted_password = self.vault.set_encrypted_data(self.master_key, password) # key, data
		return encrypted_password

	def create_password_entry(self):
		entry = collect_data()

		encrypted_password = self.set_encrypted_password()

		p = dbm.Password(group_id=entry.group_id,
						account_name=entry.account_name,
						login=entry.login,
						url=entry.url,
						encrypted_password=encrypted_password,
						memo=entry.memo)
		try:
			self.session.add(p)
			self.session.commit()
		except sqlalchemy.exc.DataError as err:
			print('***** DataError! occured *****')
			print(err)
			self.session.rollback()
		except sqlalchemy.exc.IntegrityError as err:
			print('***** IntegrityError occured! ******')
			print(err)
			self.session.rollback()
		except sqlalchemy.exc.ProgrammingError as err:
			print('***** ProgrammingError occured! *****')
			print(err)
			self.session.rollback()
		else:
			print('Password successfully added!')
		return None

	def view_entries(self):
		entries = self.session.query(dbm.Password).all()
		for entry in entries:
			print(f'Account: {entry.account_name}', sep=' ')
			print(f'URL: {entry.url}', sep=' ')
			print(f'Group: {entry.group_id}', sep=' ')
			print(f'Memo: {entry.memo}')
		print('***** All entries read! *****')

	def close_database(self):
		self.session.close()
		return None


def collect_data():
	test_data = config.TestEntry()
	account_name = test_data.ACCOUNT_NAME or input('Input account name >>>>')
	login = test_data.LOGIN or input('Input account login >>>>')
	url = test_data.URL or input('Input url >>>> ')
	group_id = test_data.GROUP_ID or input('Input group id >>>>')
	memo = test_data.MEMO or input('Input memo >>>>')
	return Entry(account_name=account_name, login=login, url=url, group_id=group_id, memo=memo)


if __name__ == '__main__':
	print('*' * 125)

	import config
	test_config = config.TestConfig()

	MASTER_PASSWORD = test_config.MASTER_PASSWORD
	PATH = test_config.DIRECTORY + os.sep + test_config.DATABASE_NAME

	db = Database(MASTER_PASSWORD, PATH)
	# print('Changing master_password...')
	# db.change_master_password('supermegapassword')
	# print('Changing master_password...')
	# db.change_master_password('anothermegapassword')
	# print('Done!')

	data = collect_data()
	# for d in data:
	# 	print(d)

	# db.create_password_entry()
	# db.view_entries()
	# db.update_password(id=10001)
	data = db.session.query(dbm.Password).filter(dbm.Password.id==10001).first()
	password = db.vault.get_decrypted_data(db.master_key, data.encrypted_password)
	print('Password retrieved!')
	print(password)
	print(password.hex())
	print('Done!')
