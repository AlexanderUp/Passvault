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

from Cryptodome import Random

from config import Config


PASSWORD_SIZE = 32
MAX_ROW_COUNT = 100
ENTRY_FIELDS = ('group_id', 'account_name', 'login', 'url', 'memo')
VAULT_ID_LENGHT = 32

# database structure (not fully implemented!):
# TABLE vault
#	* id
#	* vault_id
#	* creation date and time
#	* modification date and time
#	* encrypted_enc_key
#	* sha256(encrypted_enc_key)
#	* version of database schema
#	* version of cryptographycal function applied
#	* version of module
# TABLE entries (TABLE password)
#	* id (generally, entry number)
#	* group_id
#	* account_name
#	* login
#	* url
#	* encrypted password
#	* memo
# TABLE trashbin (deleted entries)
#	* id (generally, entry number)
#	* previous_id
#	* account_name
#	* login
#	* url
#	* encrypted password
#	* memo
# TABLE groups
#	* group_id
#	* group_name


class Database(Passvault.Vault):

	def __init__(self, path=None):
		self.conn = None
		self.cur = None
		self.enc_key = None

	def init_vault_id(self):
		vault_id = Random.new().read(VAULT_ID_LENGHT)
		return Passvault.Vault.encode_base64(vault_id)

	def init_encrypted_enc_key(self, password, enc_key):
		f = Passvault.Vault()
		enc_key = f.pre_encrypt_data(enc_key)
		if password:
			encrypted_enc_key = f.encrypt_enc_key(password, enc_key)
		else:
			raise ValueError('Empty password')
		return f.post_encrypt_data(encrypted_enc_key)

	def create_database(self, password, path=None):
		vault_id = self.init_vault_id()
		enc_key = self.get_random_key()
		# password = input('Input password...\n>>> ')
		encrypted_enc_key = self.init_encrypted_enc_key(password, enc_key)
		try:
			self.conn = sqlite3.connect(path)
			self.cur = self.conn.cursor()
			self.cur.execute('CREATE table vault(id INTEGER PRIMARY KEY, vault_id NOT NULL, encrypted_enc_key NOT NULL)')
			self.cur.execute('CREATE table password(id INTEGER PRIMARY KEY, group_id NOT NULL, account_name NOT NULL, login, url, enc_password NOT NULL, memo TEXT)')
			self.cur.execute('CREATE table trashbin(id INTEGER PRIMARY KEY, previous_id INTEGER NOT NULL, group_id NOT NULL, account_name NOT NULL, login NOT NULL, url NOT NULL, enc_password NOT NULL, memo TEXT)')
			self.cur.execute('CREATE table groups(group_id INTEGER PRIMARY KEY, group_name NOT NULL)')
			self.cur.execute('INSERT INTO vault (vault_id, encrypted_enc_key) VALUES(?, ?)', (vault_id, encrypted_enc_key))
			self.conn.commit()
		except sqlite3.DatabaseError as err:
			print('Error during database creation!\n{}'.format(err))
		else:
			print('Database created!')
			print('Path to database:')
			print(path)
		return None

	def open_database(self, path=Config.DIRECTORY):
		path_to_directory, database_name = os.path.split(path)
		print('path: {}'.format(path_to_directory))
		if os.path.exists(path):
			print('Database exists!')
			try:
				self.conn = sqlite3.connect(path)
			except Exception as err:
				print('The following error during connection to vault occured:')
				print(err)
			else:
				self.cur = self.conn.cursor()
		else:
			print('Path doesn\'t exists. Creating....')
			self.create_database(path)
		return None

	def decrypt_master_password(self, master_password):
		self.cur.execute('SELECT encrypted_enc_key FROM vault')
		encrypted_enc_key = self.cur.fetchone()[0] # without index tuple returned!
		# print('Got encrypted_enc_key:\n{}'.format(encrypted_enc_key))
		encrypted_enc_key = self.pre_decrypt_data(encrypted_enc_key)
		enc_key = self.decrypt_enc_key(master_password, encrypted_enc_key)
		self.enc_key = self.post_decrypt_data(enc_key)
		print('Password decrypted sucсessfully!')
		return None

	def change_password(self, conn, cur):
		f = Entry()
		enc_key = f.decrypt_master_password(conn, cur)
		# print('enc_key: {}'.format(enc_key))
		new_password = input('Enter new master password...\n>>> ')
		enc_key = f.pre_encrypt_data(enc_key)
		encrypted_enc_key = f.encrypt_enc_key(new_password, enc_key)
		encrypted_enc_key = f.post_encrypt_data(encrypted_enc_key)
		# print('New encrypted enc_key:\n{}'.format(encrypted_enc_key))
		try:
			cur.execute('UPDATE vault SET encrypted_enc_key=(?) WHERE id="1"', (encrypted_enc_key,)) # tuple or not??
		except sqlite3.DatabaseError as err:
			print('Error: {}'.format(err))
		else:
			conn.commit()
		finally:
			del enc_key
			del new_password
		return None

	def change_master_password(self):
		'''
		Produce new master key, decrypt all entries with old master password,
		encrypt them back using new master password.
		'''
		pass

	def create_entry(self, conn, cur, enc_key):
		data = {}
		for field in ENTRY_FIELDS:
			data[field] = input('Input {}....\n>>> '.format(field))
		# for debugging only
		# print('Data collected:\n{}'.format(data))
		password = Passvault.Vault.get_random_key()
		t = Passvault.Vault()
		iv = t.iv()
		password = t.pre_encrypt_data(password)
		enc_password = t.encrypt(enc_key, iv, password)
		enc_password = t.post_encrypt_data(enc_password)
		data['enc_password'] = enc_password
		try:
			cur.execute('INSERT INTO password (group_id, account_name, login, url, enc_password, memo) VALUES (:group_id, :account_name, :login, :url, :enc_password, :memo)', data)
		except sqlite3.DatabaseError as err:
			print('Error: {}'.format(err))
		else:
			print('Entry was successfully created!')
			conn.commit()
		del enc_key
		del password
		del enc_password
		return None

	def get_entry_key(self, conn, cur, id_, enc_key):
		try:
			cur.execute('SELECT enc_password FROM password WHERE id=(?)', (id_,))
		except sqlite3.DatabaseError as err:
			print('Error: {}'.format(err))
		else:
			enc_password = cur.fetchone()[0]
		f = Passvault.Vault()
		enc_password = f.pre_decrypt_data(enc_password)
		password = f.decrypt(enc_key, enc_password)
		password = f.post_decrypt_data(password)
		return f.encode_base64(password)

	def update_entry(self, conn, cur, id_, enc_key, data):
		try:
			for field in data.keys():
				if data[field]:
					# print('field: {}; value: {}'.format(field, data[field]))
					ins = 'UPDATE password SET {}=(?) WHERE id={}'.format(field, id_)
					cur.execute(ins, (data[field],))
				else:
					continue
		except sqlite3.DatabaseError as err:
			print('Error: {}'.format(err))
		else:
			conn.commit()
			print('Entry successfully updated!')
		return None

	# deleted entry to be moved to trash tables and to be finally deleted
	# upon time expiring (for example, 30 days after deletion)
	def delete_entry(self, conn, cur, id_):
		# id to be checked
		ins = 'INSERT INTO trashbin(previous_id, group_id, account_name, login, url, enc_password, memo) VALUES(?, ?, ?, ?, ?, ?, ?)'
		try:
			cur.execute('SELECT * FROM password WHERE id=(?)', (id_,))
			entry = cur.fetchone()
			print('Entry: {}'.format(entry))
			cur.execute(ins, entry)
		except sqlite3.DatabaseError as err:
			print('Error: {}'.format(err))
		else:
			try:
				cur.execute('DELETE FROM password WHERE id=(?)', (id_,))
			except sqlite3.DatabaseError as err:
				print('Error: {}'.format(err))
			else:
				conn.commit()
				print('Successfully deleted!')
		return None

	def get_list_of_entries(self, conn, cur):
		try:
			cur.execute('SELECT id, account_name FROM password')
		except sqlite3.DatabaseError as err:
			print('Error: {}'.format(err))
		else:
			list_of_entries = cur.fetchall() # tuple returned!
			print('Available entries:')
			print('-id-  ----name----')
			for entry in list_of_entries:
				print('#', entry[0], ':', entry[1])
		return None

	# update password for specified entry
	def update_password(self, conn, cur, id_):
		new_password = Random.new().read(PASSWORD_SIZE)
		enc_key = self.decrypt_master_password(conn, cur)
		print('Got entry key: {}'.format(enc_key))
		encrypted_password = self.pre_encrypt_data(new_password)
		iv = self.iv()
		encrypted_password = self.encrypt(enc_key, iv, encrypted_password)
		encrypted_password = self.post_encrypt_data(encrypted_password)
		# copy entry to be updated into trashbin table
		try:
			cur.execute('SELECT * FROM password WHERE id=(?)', (id_,))
			entry = cur.fetchone()
			print('Got entry: {}'.format(entry))
			ins = 'INSERT INTO trashbin(previous_id, group_id, account_name, login, url, enc_password, memo) VALUES(?, ?, ?, ?, ?, ?, ?)'
			cur.execute(ins, entry)
			print('Successfully inserted!')
		except sqlite3.DatabaseError as err:
			print('Error: {}'.format(err))
		else:
			try:
				cur.execute('UPDATE password SET enc_password=(?) WHERE id=(?)', (encrypted_password, id_))
				conn.commit()
				print('Successfully updated!')
			except sqlite3.DatabaseError as err:
				print('Error: {}'.format(err))
		finally:
			del new_password
			del enc_key
		return None

	# checks time passed since entry deletion and finally deletes entry if neccessary
	def cleanup(self, conn, cur):
		try:
			cur.execute('SELECT COUNT(id) FROM trashbin')
			row_count = cur.fetchone()
			row_count = row_count[0]
			print('Current row count is: {}'.format(row_count))
			if row_count >= MAX_ROW_COUNT:
				cur.execute('SELECT id FROM trashbin')
				id_tuple = cur.fetchone()
				# tuple of ids to be deleted
				id_tuple = id_tuple[:MAX_ROW_COUNT]
				for id in id_tuple:
					cur.execute('DELETE FROM trashbin WHERE id=(?)', id)
				# for i in range(MAX_ROW_COUNT, row_count):
				# 	# to be checked
				# 	cur.execute('DELETE FROM trashbin WHERE id=(,)', i)
				# print('Successfully deleted {} entries'.format(row_count - MAX_ROW_COUNT))
				print('Successfully deleted {} entries'.format(len(id_tuple)))
				conn.commit()
			else:
				print('Nothing to delete!')
		except sqlite3.DatabaseError as err:
			print('Error: {}'.format(err))
		return None

	def check_password(self, password):
		# import re => compile ???
		pass
