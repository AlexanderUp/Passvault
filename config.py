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
