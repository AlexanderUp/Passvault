# encoding:utf-8

# forgered database creation

import os
import sqlalchemy
import forgery_py
import database_model as dbm
from random import randint
from config import TestConfig


DIRECTORY = TestConfig.__dict__['DIRECTORY']
DATABASE_NAME = TestConfig.__dict__['DATABASE_NAME']
# DIRECTORY = TestConfig.DIRECTORY
# DATABASE_NAME = TestConfig.DATABASE_NAME
COUNT = 100

path = DIRECTORY + os.sep + DATABASE_NAME
session = dbm.init_db(path)

if __name__ == '__main__':
    print('*' * 125)
    print(DIRECTORY + os.sep + DATABASE_NAME)
    for i in range(COUNT):
        for j in range(COUNT):
            login = forgery_py.internet.email_address()
            url = forgery_py.internet.domain_name()
            encrypted_password = forgery_py.basic.text()
            memo = forgery_py.lorem_ipsum.paragraph()
            account_name = login + '-' + url
            p = dbm.Password(group_id=randint(1, 10), \
                             account_name=account_name, \
                             login=login, \
                             url=url, \
                             encrypted_password=encrypted_password, \
                             memo=memo)
            session.add(p)
        try:
            session.commit()
        except sqlalchemy.exc.IntegrityError as err:
            print('Error occured:')
            print(err)
            session.rollback()
            continue
        else:
            print('count: {}'.format(i))
    print('Done!')
