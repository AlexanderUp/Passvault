# encoding:utf-8
# Class represents password entry

# Each entry should be encrypted with randomly generated key,
# which should be encrypted with master key and stored in password database.
# Master key should be able to be changed.

# not implemented yet
# Each Vault should have own id.
# Each Vault should have authenticated number of entries.

# not implemented yet
# Every entry initializes with randomly generated password, salt and iv
# Every entry authenticated with hmac - sha3_256
# Every entry store hmac digest in separate field

# enc_key - random key used to encrypt user passwords provided by Cryptodome.Random
# stored_enc_key - encrypted and stored master_key
# password - user password used in PBKDF2 for encription/decryption of master_key

# not implemented yet
# all data => sqlite3, data export or text backup or visual representation => xml/json


import os
import sys
import sqlite3
import Passvault
import database_model as dbm

from Cryptodome import Random

from config import Config


PASSWORD_SIZE = 32
MAX_ROW_COUNT = 100
ENTRY_FIELDS = ('group_id', 'account_name', 'login', 'url', 'memo')
VAULT_ID_LENGHT = 32

'''
database structure (not fully implemented!):
TABLE vault
	* id
	* vault_id
	* creation date and time
	* modification date and time
	* encrypted_enc_key
	* sha256(encrypted_enc_key)
	* version of database schema
	* version of cryptographycal function applied
	* version of module
TABLE entries (TABLE password)
	* id (generally, entry number)
	* group_id
	* account_name
	* login
	* url
	* encrypted password
	* memo
TABLE trashbin (deleted entries)
	* id (generally, entry number)
	* previous_id
	* account_name
	* login
	* url
	* encrypted password
	* memo
TABLE groups
	* group_id
	* group_name
'''


class Database(Passvault.Vault):

	def __init__(self, path=None):
		# self.conn = None
		# self.cur = None
		self.enc_key = None
		self.master_password = Config['MASTER_PASSWORD']
		self.path = Config['DIRECTORY'] + os.sep + Config['DATABASE_NAME']
		self.session = dbm.init_db(self.path)

	def init_vault_id(self):
		vault_id = Random.new().read(VAULT_ID_LENGHT)
		return Passvault.Vault.encode_base64(vault_id)

	def init_encrypted_enc_key(self, password, enc_key):
		f = Passvault.Vault()
		enc_key = f.pre_encrypt_data(enc_key)
		encrypted_enc_key = f.encrypt_enc_key(password, enc_key)
		return f.post_encrypt_data(encrypted_enc_key)

	def init_database(self, password):
		vault_id_ = self.init_vault_id()
		enc_key = self.get_random_key()
		encrypted_enc_key_ = self.init_encrypted_enc_key(password, enc_key)
		try:
			vault = dbm.Vault(vault_id=vault_id_, encrypted_enc_key=encrypted_enc_key_, \
								db_schema_version='1', crypto_version='1', passvault_app_version='1')
			self.session.add(vault)
			self.session.commit()
		except Exception as err:
			print('Error occured')
			print(err)
			self.session.rollback()
		return None

	def decrypt_enc_key(self, master_password):
		encrypted_enc_key = self.session.query(dbm.Vault.encrypted_enc_key).first()
		encrypted_enc_key = self.pre_decrypt_data(encrypted_enc_key)
		# TODO: try-except-else-finally
		enc_key = self.decrypt_enc_key(master_password, encrypted_enc_key)
		self.enc_key = self.post_decrypt_data(enc_key)
		print('Password decrypted sucсessfully!')
		return None

	# TODO
	# def change_password(self, conn, cur):
	# 	f = Entry()
	# 	enc_key = f.decrypt_master_password(conn, cur)
	# 	# print('enc_key: {}'.format(enc_key))
	# 	new_password = input('Enter new master password...\n>>> ')
	# 	enc_key = f.pre_encrypt_data(enc_key)
	# 	encrypted_enc_key = f.encrypt_enc_key(new_password, enc_key)
	# 	encrypted_enc_key = f.post_encrypt_data(encrypted_enc_key)
	# 	# print('New encrypted enc_key:\n{}'.format(encrypted_enc_key))
	# 	try:
	# 		cur.execute('UPDATE vault SET encrypted_enc_key=(?) WHERE id="1"', (encrypted_enc_key,)) # tuple or not??
	# 	except sqlite3.DatabaseError as err:
	# 		print('Error: {}'.format(err))
	# 	else:
	# 		conn.commit()
	# 	finally:
	# 		del enc_key
	# 		del new_password
	# 	return None

	# TODO
	# def change_master_password(self):
	# 	'''
	# 	Produce new master key, decrypt all entries with old master password,
	# 	encrypt them back using new master password.
	# 	'''
	# 	pass

	def set_encrypted_password(self):
		vault = Passvault.Vault()
		password = vault.get_random_key() # self.get_random_key
		encrypted_password = vault.set_encrypted_data(self.enc_key, password) # key, data
		return encrypted_password

	def create_password_entry(self, conn, cur, enc_key):
		data = {}
		for field in ENTRY_FIELDS:
			data[field] = input('Input {}....\n>>> '.format(field))
		# for debugging only
		# print('Data collected:\n{}'.format(data))
		for (item, value) in data.items():
			print(item, '==>>', value)
		t = Passvault.Vault()
		password = t.get_random_key()
		iv = t.iv()
		password = t.pre_encrypt_data(password)
		enc_password = t.encrypt(enc_key, iv, password)
		enc_password = t.post_encrypt_data(enc_password)
		data['enc_password'] = enc_password
		p = dbm.Password(group_id=data['group_id'], account_name=data['account_name'], \
						login=data['login'], url=data['url'], encrypted_password=enc_password, \
						memo=data['memo'])
		try:
			self.session.add(p)
			self.session.commit()
		except DataError as err:
			print('DataError occured:')
			print(err)
			self.session.rollback()
		except IntegrityError as err:
			print('IntegrityError occured:')
			print(err)
			self.session.rollback()
		except ProgrammingError as err:
			print('ProgrammingError occured:')
			print(err)
			self.session.rollback()
		else:
			print('Password successfully added!')
		return None

	# def update_entry(self, conn, cur, id_, enc_key, data):
	# 	try:
	# 		for field in data.keys():
	# 			if data[field]:
	# 				# print('field: {}; value: {}'.format(field, data[field]))
	# 				ins = 'UPDATE password SET {}=(?) WHERE id={}'.format(field, id_)
	# 				cur.execute(ins, (data[field],))
	# 			else:
	# 				continue
	# 	except sqlite3.DatabaseError as err:
	# 		print('Error: {}'.format(err))
	# 	else:
	# 		conn.commit()
	# 		print('Entry successfully updated!')
	# 	return None

	# deleted entry to be moved to trash tables and to be finally deleted
	# upon time expiring (for example, 30 days after deletion)
	# def delete_entry(self, conn, cur, id_):
	# 	# id to be checked
	# 	ins = 'INSERT INTO trashbin(previous_id, group_id, account_name, login, url, enc_password, memo) VALUES(?, ?, ?, ?, ?, ?, ?)'
	# 	try:
	# 		cur.execute('SELECT * FROM password WHERE id=(?)', (id_,))
	# 		entry = cur.fetchone()
	# 		print('Entry: {}'.format(entry))
	# 		cur.execute(ins, entry)
	# 	except sqlite3.DatabaseError as err:
	# 		print('Error: {}'.format(err))
	# 	else:
	# 		try:
	# 			cur.execute('DELETE FROM password WHERE id=(?)', (id_,))
	# 		except sqlite3.DatabaseError as err:
	# 			print('Error: {}'.format(err))
	# 		else:
	# 			conn.commit()
	# 			print('Successfully deleted!')
	# 	return None

	def get_list_of_entries(self, conn, cur):
		entries = []
		try:
			entries.extend(self.session.query(dbm.Password).all())
		except ProgrammingError as err:
			print(err)
		else:
			print('List of entries gotten successfully!')
		print('Available entries:')
		for entry in entries:
			print(entry)
		return None

	# # update password for specified entry
	# def update_password(self, conn, cur, id_):
	# 	new_password = Random.new().read(PASSWORD_SIZE)
	# 	enc_key = self.decrypt_master_password(conn, cur)
	# 	print('Got entry key: {}'.format(enc_key))
	# 	encrypted_password = self.pre_encrypt_data(new_password)
	# 	iv = self.iv()
	# 	encrypted_password = self.encrypt(enc_key, iv, encrypted_password)
	# 	encrypted_password = self.post_encrypt_data(encrypted_password)
	# 	# copy entry to be updated into trashbin table
	# 	try:
	# 		cur.execute('SELECT * FROM password WHERE id=(?)', (id_,))
	# 		entry = cur.fetchone()
	# 		print('Got entry: {}'.format(entry))
	# 		ins = 'INSERT INTO trashbin(previous_id, group_id, account_name, login, url, enc_password, memo) VALUES(?, ?, ?, ?, ?, ?, ?)'
	# 		cur.execute(ins, entry)
	# 		print('Successfully inserted!')
	# 	except sqlite3.DatabaseError as err:
	# 		print('Error: {}'.format(err))
	# 	else:
	# 		try:
	# 			cur.execute('UPDATE password SET enc_password=(?) WHERE id=(?)', (encrypted_password, id_))
	# 			conn.commit()
	# 			print('Successfully updated!')
	# 		except sqlite3.DatabaseError as err:
	# 			print('Error: {}'.format(err))
	# 	finally:
	# 		del new_password
	# 		del enc_key
	# 	return None

	# # checks time passed since entry deletion and finally deletes entry if neccessary
	# def cleanup(self, conn, cur):
	# 	try:
	# 		cur.execute('SELECT COUNT(id) FROM trashbin')
	# 		row_count = cur.fetchone()
	# 		row_count = row_count[0]
	# 		print('Current row count is: {}'.format(row_count))
	# 		if row_count >= MAX_ROW_COUNT:
	# 			cur.execute('SELECT id FROM trashbin')
	# 			id_tuple = cur.fetchone()
	# 			# tuple of ids to be deleted
	# 			id_tuple = id_tuple[:MAX_ROW_COUNT]
	# 			for id in id_tuple:
	# 				cur.execute('DELETE FROM trashbin WHERE id=(?)', id)
	# 			# for i in range(MAX_ROW_COUNT, row_count):
	# 			# 	# to be checked
	# 			# 	cur.execute('DELETE FROM trashbin WHERE id=(,)', i)
	# 			# print('Successfully deleted {} entries'.format(row_count - MAX_ROW_COUNT))
	# 			print('Successfully deleted {} entries'.format(len(id_tuple)))
	# 			conn.commit()
	# 		else:
	# 			print('Nothing to delete!')
	# 	except sqlite3.DatabaseError as err:
	# 		print('Error: {}'.format(err))
	# 	return None
	#
	# def check_password(self, password):
	# 	# import re => compile ???
	# 	pass
