# encoding:utf-8

import os


class Config():
    DIRECTORY = os.environ.get('DIRECTORY')
    DATABASE_NAME = os.environ.get('DATABASE_NAME')
    MASTER_PASSWORD = os.environ.get('MASTER_PASSWORD') or 'testtesttest'


class TestConfig():
    DIRECTORY = os.environ.get('DIRECTORY')
    DATABASE_NAME = 'test_' + os.environ.get('DATABASE_NAME')
    MASTER_PASSWORD = 'testtesttest'


class TestEntry():
	ACCOUNT_NAME = 'Rick Sanchezzz Mail'
	LOGIN = 'Rick Sanchezzz Matherfucker'
	URL = 'rick.sanchezzz@mail.space'
	GROUP_ID = 'Mail'
	MEMO = 'Do not tell password to Morty!'


class FileCryptorTestConfig():
    PLAIN_FILE = os.environ.get('PLAIN_FILE')
    MASTER_PASSWORD = bytes(os.environ.get('MASTER_PASSWORD'), 'utf-8')
