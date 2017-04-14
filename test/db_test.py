"""Unit tests for datastore"""

import unittest
import tempfile

import db #db.py

class DBTest(unittest.TestCase):
    """Test functionality of DB functions"""
    def setUp(self):
        db_temp_file = tempfile.NamedTemporaryFile()
        self.db_file = db_temp_file
        self.db_con = db.Datastore(filename=self.db_file.name)

    def tearDown(self):
        self.db_con.close()

    def test_set_one_record_and_retrieve(self):
        """Set one dummy WHOIS record and retrieve it"""
        record = 'foo'
        domain = 'example.com'
        self.db_con.set_record(domain=domain, record=record)
        retrieved_record = self.db_con.get_record(domain=domain)
        self.assertEqual(record, retrieved_record)

    def test_no_record_error(self):
        """When no record is set for domain, should throw error"""
        with self.assertRaises(db.NoWhoisRecordStoredError):
            self.db_con.get_record(domain='noexist.com')

    def test_get_cooldown_without_record(self):
        """If we try to fetch the cooldown without a record, should throw"""
        with self.assertRaises(db.NoWhoisRecordStoredError):
            self.db_con.cooldown_sec_remaining(domain='noexist.com')

    def test_get_cooldown_with_record(self):
        """Getting cooldown for domain none is stored returns 0"""
        record = 'foo'
        domain = 'example.com'
        self.db_con.set_record(domain=domain, record=record)
        cooldown_remaining = self.db_con.cooldown_sec_remaining(domain=domain)
        self.assertEqual(cooldown_remaining, 0)

    def test_set_cooldown_no_record(self):
        """Setting cooldown on a domain w/o stored record creates exception"""
        domain = 'example.com'
        cooldown = 42
        with self.assertRaises(db.NoWhoisRecordStoredError):
            self.db_con.set_cooldown(domain, cooldown)

    def test_set_cooldown_with_record(self):
        """Set cooldown for domain with record and confirm it's stored correctly"""
        domain = 'example.com'
        record = 'foo'
        cooldown = 42
        self.db_con.set_record(domain=domain, record=record)
        self.db_con.set_cooldown(domain=domain, sec_remaining=cooldown)
        remaining = self.db_con.cooldown_sec_remaining(domain=domain)
        #some time may have passed between when cooldown was set and now
        self.assertGreaterEqual(remaining, 1)
        self.assertLessEqual(remaining, cooldown)
