# encoding:utf-8

# forgered database creation

import os
import sqlalchemy
import forgery_py
import database_model as dbm
import init_database

from sqlalchemy import create_engine
from sqlalchemy.orm import mapper
from sqlalchemy.orm import sessionmaker
from random import randint
from config import TestConfig


DIRECTORY = TestConfig.__dict__['DIRECTORY']
DATABASE_NAME = TestConfig.__dict__['DATABASE_NAME']
# DIRECTORY = TestConfig.DIRECTORY
# DATABASE_NAME = TestConfig.DATABASE_NAME
MASTER_PASSWORD = TestConfig.__dict__['MASTER_PASSWORD']
COUNT = 100


if __name__ == '__main__':
    print('*' * 125)
    path = DIRECTORY + os.sep + DATABASE_NAME
    print(DIRECTORY + os.sep + DATABASE_NAME)

    engine = create_engine('sqlite:///' + path)
    dbm.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    print('Engine created!')

    dbi = init_database.DBInitializer(path)
    dbi.init_database(MASTER_PASSWORD)

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
