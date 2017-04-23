"""Unit tests for app.py

Usage:
    $ cd whoisalert
    $ make test

Todos:
    * Add AppTest for coming back from cooldown, but ideally without a sleep().
    * Add AppTest to ensure no email is sent when no changes are detected.
"""
import unittest
import tempfile
import os
import re

import app #app.py
import db #db.py

ENABLE_DEBUG_PRINT = False

class HelperTest(unittest.TestCase):
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
        """Parse record containing cooldown info

        Reference:
        http://registrars.nominet.uk/namespace/uk/registration-and-domain-management/query-tools/whois/detailed-instructions
        """
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

    def test_recipient_parsing(self):
        """Parse a list of recipients and channels"""
        filename = './test/sample_recipientslist.csv'
        recipients = app.get_recipients(filename)
        self.assertEqual(len(recipients), 2)
        self.assertEqual(recipients[0][0], 'alice@example.com')
        self.assertEqual(recipients[0][1], 'email')
        self.assertEqual(recipients[1][0], 'bob@example.com')
        self.assertEqual(recipients[1][1], 'email_simulated_file')

    def test_send_simulated_email(self):
        """Simulate the sending of an email"""

        recipient = tempfile.NamedTemporaryFile(delete=False).name
        try:
            smtp_auth = dict()

            subject = 'TEST subject'
            body = 'TEST this is a simulated email'
            app.send_email(smtp_auth=smtp_auth, recipient=recipient,
                           subject=subject, body=body, simulate=True)

            #verify the correct email contents were written
            with open(recipient, 'r') as email_simulated_file:
                lines = email_simulated_file.readlines()
                self.assertEqual(lines[0], "From: {0}\n".format(
                    app.SIMULATED_SENDER_EMAIL))
                self.assertEqual(lines[1], "To: {0}\n".format(recipient))
                self.assertEqual(lines[2], "Subject: {0}\n".format(subject))
                self.assertEqual(lines[3], "\n")
                self.assertEqual(lines[4], body)
        finally:
            os.remove(recipient)

class AppTest(unittest.TestCase):
    """Test high-level functionality of app from main()

    Since these are unit tests, network calls to WHOIS servers are avoided.
    """
    def setUp(self):
        #a list of files to clean up that actually exist
        self.tempfiles = []

        #Create temporary database file to avoid corrupting user database
        db_file = tempfile.NamedTemporaryFile(suffix='.db', delete=False).name
        self.tempfiles.append(db_file)
        self.db_con = db.Datastore(filename=db_file)

        #contains these domains: google.com, yahoo.com, blockchain.info
        self.domain_list = './test/sample_domainlist.txt'

        #Set dummy record for the domains we're simulating a change to.
        #This will prevent the app from attempting to pre-fill the record by
        #making a network WHOIS request.
        dummy = 'aTHIS IS A DUMMY WHOIS RECORD'
        self.test_domains = ('google.com', 'yahoo.com', 'blockchain.info')
        for domain in self.test_domains:
            self.db_con.set_record(domain=domain, record=dummy)

        #create 2 files to store email sent to 2 simulated recipients
        self.email_simulated_files = []
        for _ in range(2):
            email_simulated_file = tempfile.NamedTemporaryFile(delete=False).name
            self.tempfiles.append(email_simulated_file)
            self.email_simulated_files.append(email_simulated_file)
            dprint("Created simulated email file {0}".format(email_simulated_file))

        #create a recipeint list file to pass as an arguments
        self.recipientlist_file = tempfile.NamedTemporaryFile(
            suffix='.csv', delete=False).name
        self.tempfiles.append(self.recipientlist_file)

        with open(self.recipientlist_file, 'w') as recip_file:
            for email_simulated_file in self.email_simulated_files:
                record = "{0},{1}\n".format(
                    email_simulated_file, 'email_simulated_file')
                recip_file.write(record)

    def tearDown(self):
        for _file in self.tempfiles:
            print "Cleanup: Removing {0}...".format(_file)
            os.remove(_file)

    def assertMatches(self, pattern, _string, fail=None):
        """The pattern matches the string"""
        if fail is None:
            self.assertIsNotNone(re.match(pattern, _string))
        else:
            self.assertIsNotNone(re.match(pattern, _string), fail)

    def test_simulate_change(self):
        """Simulated WHOIS record change with 2 simulated recipients

        This should result in one simulated email file written for each
        recipient.
        """
        dprint("STARTED test_simulate_change")
        argv = ('app.py', '--simulate_change', self.domain_list, self.recipientlist_file)
        app.main(argv=argv, db_con=self.db_con, check_env=False)

        dprint("completed call to app.main from test_simulate_change")

        expected_subject = ''.join(['ALERT: Modified WHOIS record for: ',
                                    ', '.join(sorted(self.test_domains))])

        #verify the correct email content was written for each simulated recipient
        for idx, email_simulated_file in enumerate(self.email_simulated_files):
            with open(email_simulated_file, 'r') as email_file:
                lines = email_file.readlines()
                self.assertGreater(len(lines), 11)
                self.assertEqual(lines[0], "From: {0}\n".format(
                    app.SIMULATED_SENDER_EMAIL))
                self.assertEqual(lines[1], "To: {0}\n".format(self.email_simulated_files[idx]))
                self.assertEqual(lines[2], "Subject: {0}\n".format(expected_subject))
                self.assertEqual(lines[3], "\n")
                self.assertEqual(lines[4], "yahoo.com:\n")
                self.assertEqual(lines[5], "\n")
                self.assertEqual(lines[6], "*** \n")
                self.assertEqual(lines[7], "--- \n")
                self.assertEqual(lines[8], "***************\n")
                self.assertEqual(lines[9], "*** 1 ****\n")
                self.assertEqual(
                    lines[10],
                    "! aTHIS IS A DUMMY WHOIS RECORD--- 1 ----\n")
                #the rest of the string will have random char changes, so
                #check only the deterministic portion.
                self.assertEqual(lines[11][0:3], "! b") # 'a' => 'b'
                #assume remaining is good...

    def test_simulate_cooldown(self):
        """Simulated initial cooldown w/ 2 simulated recipients should write file."""

        argv = ('app.py', '--simulate_cooldown', '5', self.domain_list, self.recipientlist_file)
        app.main(argv=argv, db_con=self.db_con, check_env=False)

        expected_subject_re = (r'^Subject: INFO: WHOIS queries for '
                               r'[a-zA-Z\d-]{,63}\.[a-zA-Z\d-]{,63} '
                               r'are on cooldown for \d+ second\(s\)\n$')
        expected_body_re = (
            r'^WHOIS records cannot be retrieved for '
            r'[a-zA-Z\d-]{,63}\.[a-zA-Z\d-]{,63} ' #domain
            r'for \d+ more second\(s\)\. This is your only notification during '
            r'this period\. Consider querying less often for the affected '
            r'domain to avoid blind periods\.\n$')

        #verify the correct email content was written for each simulated recipient
        for idx, email_simulated_file in enumerate(self.email_simulated_files):
            with open(email_simulated_file, 'r') as email_file:
                lines = email_file.readlines()
                self.assertEqual(len(lines), 15, lines)
                self.assertEqual(lines[0], "From: {0}\n".format(
                    app.SIMULATED_SENDER_EMAIL))
                self.assertEqual(lines[1], "To: {0}\n".format(self.email_simulated_files[idx]))
                self.assertMatches(
                    expected_subject_re,
                    lines[2],
                    "'{0}' != '{1}'".format(lines[2], expected_subject_re))
                self.assertEqual(lines[3], "\n")
                self.assertMatches(
                    expected_body_re,
                    lines[4],
                    "'{0}' != '{1}'".format(lines[4], expected_body_re))
                #we checkd the first 5 lines; the next 10 should be for the
                #other 2 of the 3 domains we simulated a cooldown for. assume
                #they are good...

    def test_cooldown_suppresses_email(self):
        """When a domain is only cooldown still, a new email won't be sent."""
        dprint("STARTED test_cooldown_suppresses_email")
        try:
            argv = ('app.py', '--simulate_cooldown', '30', self.domain_list,
                    self.recipientlist_file)
            app.main(argv=argv, db_con=self.db_con, check_env=False)


            for email_simulated_file in self.email_simulated_files:
                self.assertGreater(os.path.getsize(email_simulated_file), 0)
                #"forget" the simulated emails that were sent
                open(email_simulated_file, 'w').close()
                dprint("Zeroed simulated email file {0}".format(email_simulated_file))
                assert os.path.getsize(email_simulated_file) == 0

            dprint("ENDED cooldown simulation")
            dprint("STARTED simulate change during cooldown")

            argv = ('app.py', '--simulate_change', self.domain_list, self.recipientlist_file)
            app.main(argv=argv, db_con=self.db_con, check_env=False)

            for email_simulated_file in self.email_simulated_files:
                #no new emails sent because cooldown
                self.assertEqual(
                    os.path.getsize(email_simulated_file),
                    0,
                    open(email_simulated_file, 'r').readlines())
        finally:
            dprint("ENDED test_cooldown_suppresses_email")

def dprint(_str):
    """Debug print data"""
    if ENABLE_DEBUG_PRINT:
        print "DEBUG: {0}".format(str(_str))
