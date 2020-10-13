# encoding:utf-8
# tests for Passvault database module

import unittest

import database


class DatabaseTest(unittest.TestCase):

    def setUp(self):
        self.test_db = database.Database()

    def tearDown(self):
        pass


if __name__ == '__main__':
    unittest.main()
