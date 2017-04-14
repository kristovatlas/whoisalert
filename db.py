"""Store state about past invocations of the script.

Version 1 schema:
* TABLE: tblWhoisRecords
    * domain (TEXT)
    * record (TEXT)
    * last_fetched (INTEGER) -- seconds since epoch, UTC
    * cooldown_from_fetch (INTEGER) -- secords remaining until cooldown over
"""

import time
import tempfile
from warnings import warn

import sqliter #sqliter.py

ENABLE_DEBUG_PRINT = False

APP_NAME = 'whoisalert'
AUTHOR = 'atlas'
APP_VERSION = 2

TBL_WHOIS = sqliter.DatabaseTable()
TBL_WHOIS.name = 'tblWhoisRecords'
TBL_WHOIS.set_cols(
    (('id', 'INTEGER PRIMARY KEY AUTOINCREMENT'),
     ('domain', 'TEXT UNIQUE'),
     ('record', 'TEXT'),
     ('last_fetched', 'INTEGER'),
     ('cooldown_from_fetch', 'INTEGER')))

class NoWhoisRecordStoredError(Exception):
    """There's no WHOIS record stored for this domain"""
    pass

class Datastore(object):
    """Access and stores data for app"""

    def __init__(self, filename=None):
        if filename is None:
            self.db_con = sqliter.DatabaseConnection(
                db_tables=[TBL_WHOIS], app_tuple=(APP_NAME, AUTHOR, APP_VERSION))
        else:
            log_file = tempfile.NamedTemporaryFile()
            warn("Logging to '{0}'".format(log_file.name))

            filenames = (filename, log_file.name)

            self.db_con = sqliter.DatabaseConnection(db_tables=[TBL_WHOIS],
                                                     app_tuple=None,
                                                     filenames=filenames,
                                                     file_path_abs=True)

    def __enter__(self):
        return self

    def __exit__(self, exec_type, exec_value, exec_traceback):
        self.db_con.__exit__(exec_type, exec_value, exec_traceback)

    def close(self):
        """Close connection to databse"""
        self.db_con.conn.close()

    def set_record(self, domain, record):
        """Store the WHOIS record for the specified domain"""
        insert = True
        try:
            self.get_record(domain)
            insert = False
        except NoWhoisRecordStoredError:
            pass

        #Use Python to count time rather than SQL to avoid annoying timezone
        #complexities.
        cur_time = get_current_unix_time()
        row = {'domain': domain,
               'record': record,
               'last_fetched': cur_time,
               'cooldown_from_fetch': 0}

        if insert:
            self.db_con.insert(TBL_WHOIS, row)
        else:
            whr = sqliter.Where(TBL_WHOIS)
            self.db_con.update(col_val_map=row, where=whr.eq('domain', domain))

    def get_record(self, domain):
        """Retrieve the WHOIS record for the specified domain"""
        whr = sqliter.Where(TBL_WHOIS, limit=1)
        rows = self.db_con.select(col_names=['record'],
                                  where=whr.eq('domain', domain))
        assert len(rows) < 2
        if len(rows) == 0:
            raise NoWhoisRecordStoredError()
        return rows[0]['record']

    def cooldown_sec_remaining(self, domain):
        """Returns number of seconds in cooldown, if any

        Return:
            int: If cooldown timer was never set, returns 0. If cooldown timer
                 has expired, returns int <= 0.
        """
        whr = sqliter.Where(TBL_WHOIS, limit=1)
        rows = self.db_con.select(
            col_names=['last_fetched', 'cooldown_from_fetch'],
            where=whr.eq('domain', domain))
        if len(rows) == 0:
            raise NoWhoisRecordStoredError()
        else:
            assert len(rows) == 1

        last_fetched = int(rows[0]['last_fetched'])
        cooldown = rows[0]['cooldown_from_fetch']

        dprint("db: cooldown_sec_remaining(): last_fetched = %d cooldown = %s" %
               (last_fetched, str(cooldown)))
        if cooldown is None:
            return 0
        else:
            cur_time = get_current_unix_time()
            elapsed = cur_time - last_fetched
            remaining = int(cooldown) - elapsed
            dprint(("db: cooldown_sec_remaining(): cur_time = %d elapsed = %d "
                    "remaining = %d") % (cur_time, elapsed, remaining))
            return remaining

    def set_cooldown(self, domain, sec_remaining):
        """Set the cooldown timer for domain"""
        assert isinstance(domain, str)
        assert isinstance(sec_remaining, int)
        whr = sqliter.Where(TBL_WHOIS)
        if not self.db_con.update(
                col_val_map={'cooldown_from_fetch': sec_remaining},
                where=whr.eq('domain', domain)):

            raise NoWhoisRecordStoredError(
                "Can't set cooldown because no record is stored for this domain")

def get_current_unix_time():
    """Return current UNIX time, UTC"""
    return int(time.time())

def dprint(msg):
    """Print DEBUG message to stdout"""
    if ENABLE_DEBUG_PRINT:
        print "DEBUG: {0}".format(str(msg))
