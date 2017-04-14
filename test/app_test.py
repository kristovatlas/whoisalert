"""Unit tests for helper functions in app.py"""
import unittest
#import os

import app #app.py

#DIR_PATH = os.path.dirname(os.path.realpath(__file__))

class AppTest(unittest.TestCase):
    """Test functionality of helper functions"""
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_get_diff(self):
        """Test that two different strings return a diff"""
        str1 = 'asdf'
        str2 = 'asdff'
        self.assertNotEqual(app.get_diff(str1, str2), '')

    def test_get_nodiff(self):
        """Test that two equal strings return no diff"""
        str1 = 'asdf'
        self.assertEqual(app.get_diff(str1, str1), '')

    def test_good_domains(self):
        """Valid domain names"""
        self.assertTrue(app.is_domain_name('google.com'))
        self.assertTrue(app.is_domain_name('abc.google.com'))
        self.assertTrue(app.is_domain_name('abc.go-ogle.com'))

    def test_bad_domains(self):
        """Invalid domain names"""
        self.assertFalse(app.is_domain_name('; command injection'))

    def test_remove_dynamic_line(self):
        """Remove lines from whois record that vary by query"""
        record = """URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
        >>> Last update of WHOIS database: 2017-04-05T23:14:14Z <<<

        For more information on Whois status codes, please visit https://icann.org/epp"""

        expected = """URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/

        For more information on Whois status codes, please visit https://icann.org/epp"""
        self.assertEqual(app.remove_dynamic_line(record), expected)

        record2 = """To single out one record, look it up with "xxx", where xxx is one of the
        records displayed above. If the records are the same, look them up
        with "=xxx" to receive a full display for each record.

        >>> Last update of whois database: Thu, 06 Apr 2017 00:22:24 GMT <<<

        For more information on Whois status codes, please visit https://icann.org/epp"""

        expected2 = """To single out one record, look it up with "xxx", where xxx is one of the
        records displayed above. If the records are the same, look them up
        with "=xxx" to receive a full display for each record.


        For more information on Whois status codes, please visit https://icann.org/epp"""
        self.assertEqual(app.remove_dynamic_line(record2), expected2)

    def test_get_cooldown_sec_from_record(self):
        """Parse record containing cooldown info"""
        #From:
        #http://registrars.nominet.uk/namespace/uk/registration-and-domain-management/query-tools/whois/detailed-instructions
        record = (
            '    Error for "<domain name>". The WHOIS query quota for '
            '<xxx.xxx.xxx.xxx> has been exceeded and will be replenished in '
            '143 seconds.     \n'
            '    WHOIS lookup made at <hh:mm:ss dd-mmm-yyyy> -- '
            '<copyright text>')
        cooldown = 143
        self.assertEqual(app.get_cooldown_sec_from_record(record), cooldown)

    def test_get_cooldown_sec_from_record_negative(self):
        """Should return -1 if record does not contain a cooldown error"""
        record = """URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
        >>> Last update of WHOIS database: 2017-04-05T23:14:14Z <<<

        For more information on Whois status codes, please visit https://icann.org/epp"""

        self.assertEqual(app.get_cooldown_sec_from_record(record), app.NO_COOLDOWN)

    def test_random_flips(self):
        """First character should be incremented by 1 in value"""
        self.assertEqual(app.random_flips('abcd')[0], 'b')
