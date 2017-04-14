"""Send an email alert when the whois record for a domain changes.

Usage:

    $ python app.py [--simulate_change] [--simulate_cooldown n] domainlist.txt recipient@example.com

Either the --simulate_change option or the --simluate_cooldown option may be
used, but not both simultaneously.

Expects the following environment variables set:

    * WHOISALERT_SMTP_USERNAME
    * WHOISALERT_SMTP_PASSWORD
    * WHOISALERT_SMTP_SERVER (Optional: Defaults to 'smtp.gmail.com')
    * WHOISALERT_SMTP_PORT (Optional: Defaults to 465)

Requires:
    * 'whois' command

domainlist.txt format:
domain1\n
domain2\n
...
"""

import difflib
import smtplib
import logging
import os
import sys
import re
import subprocess
import random

import db #db.py

LOG_FILENAME = 'whoisalert.log'
DEFAULT_SMTP_SERVER = 'smtp.gmail.com'
DEFAULT_SMTP_PORT = 465

DEFAULT_MAP = {'WHOISALERT_SMTP_SERVER': DEFAULT_SMTP_SERVER,
               'WHOISALERT_SMTP_PORT': DEFAULT_SMTP_PORT}

DOMAIN_NAME = r'^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$'

SIMULATE_RANDOMIZE_FREQUENCY = 0.05

#A list of strings that indicate the line should be ignored in the WHOIS response
WHOIS_LINES_IGNORE = ('Last update of WHOIS database',
                      'WHOIS lookup made at ')

#A list of strings that indicate a line is alerting quota is exceeded
WHOIS_LINES_COOLDOWN = ('The WHOIS query quota',)

NO_COOLDOWN = -1

class DomainOnCooldownError(Exception):
    """A previous WHOIS record response indicated this domain is on cooldown. Wait."""
    pass

class NoCachedRecordError(Exception):
    """No previous WHOIS record cached for this domain"""
    pass

def remove_dynamic_line(whois_record):
    """Remove the line from the record that changes per query"""
    result = ''
    for line in whois_record.split("\n"):
        ignore = False
        for ignore_line in WHOIS_LINES_IGNORE:
            if re.search(ignore_line, line, flags=re.IGNORECASE) is not None:
                ignore = True
                break
        if not ignore:
            if result == '': #first non-ignored line in record
                result = line
            else:
                result = "\n".join([result, line])
    return result

def get_diff(str1, str2):
    """Get diff between the two strings. If no diff, return empty string."""
    '''
    result = ''
    for line in difflib.ndiff(str1, str2):
        result = '\n'.join([result, line])
    return result
    '''
    #ignore lines that are not part of WHOIS record but change each query
    str1 = remove_dynamic_line(str1)
    str2 = remove_dynamic_line(str2)

    return ''.join(difflib.context_diff(str1.split("\n"), str2.split("\n")))

def get_env(env_var_name, use_default=False):
    """Get environment variable or (use default or exit with error)"""
    val = os.getenv(env_var_name, None)
    if val is None:
        if use_default and env_var_name in DEFAULT_MAP:
            return DEFAULT_MAP[env_var_name]

        msg = "No value provided for environment variable '{0}'".format(
            env_var_name)
        log(msg, level=logging.ERROR)
        sys.exit(msg)
    return val

def send_cooldown_notification(recipient, domain, cooldown_sec):
    """Send email alerting that domain is on cooldown for WHOIS lookups"""
    smtp_auth = dict()
    smtp_auth['username'] = get_env('WHOISALERT_SMTP_USERNAME')
    smtp_auth['password'] = get_env('WHOISALERT_SMTP_PASSWORD')
    smtp_auth['server'] = get_env('WHOISALERT_SMTP_SERVER', use_default=True)
    smtp_auth['port'] = get_env('WHOISALERT_SMTP_PORT', use_default=True)

    subject = 'INFO: WHOIS queries for {0} are on cooldown for {1} second(s)'.format(
        domain, str(cooldown_sec))
    body = ('WHOIS records cannot be retrieved for {0} for {1} more second(s). '
            'This is your only notification during this period. Consider '
            'querying less often for the affected domain to avoid blind '
            'periods.').format(domain, cooldown_sec)

    send_email(smtp_auth, recipient, subject, body)

def send_alert(recipient, affected_domain_diffs):
    """Send email alert

    Args:
        recipient (str): Email address to send email to
        affected_domain_diffs (dict): Maps domain names whose WHOIS records
            have changed to the diff strings. {'example.com' => '---...'}
    """
    smtp_auth = dict()
    smtp_auth['username'] = get_env('WHOISALERT_SMTP_USERNAME')
    smtp_auth['password'] = get_env('WHOISALERT_SMTP_PASSWORD')
    smtp_auth['server'] = get_env('WHOISALERT_SMTP_SERVER', use_default=True)
    smtp_auth['port'] = get_env('WHOISALERT_SMTP_PORT', use_default=True)

    subject = 'ALERT: Modified WHOIS record for: '
    subject += ', '.join(affected_domain_diffs.keys())

    body = ''
    for domain in affected_domain_diffs.keys():
        body = ''.join([body, "{0}:\n\n".format(domain)])
        body = ''.join([body, affected_domain_diffs[domain], "\n\n"])

    send_email(smtp_auth, recipient, subject, body)

def send_email(smtp_auth, recipient, subject, body):
    """Send email via SMTP.
    Args:
        smtp_auth (dict): Contains 'username' (str), 'password' (str),
            'server' (str), and 'port' (int)
        recipient (str): The email address to send to
        subject (str)
        body (str)
    http://stackoverflow.com/questions/10147455/trying-to-send-email-gmail-as-mail-provider-using-python
    """
    email_to = [recipient]

    #Sending message, first construct actual message
    message = ("From: %s\nTo: %s\nSubject: %s\n\n%s" %
               (smtp_auth['username'], ", ".join(email_to), subject, body))
    try:
        server_ssl = smtplib.SMTP_SSL(smtp_auth['server'], 465)
        server_ssl.ehlo()
        server_ssl.login(smtp_auth['username'], smtp_auth['password'])
        server_ssl.sendmail(smtp_auth['username'], email_to, message)
        server_ssl.close()
    except Exception, err:
        msg = "Failed to send mail: %s" % str(err)
        log(msg, logging.ERROR)
        sys.exit(msg)

    msg = "Email sent to %s." % recipient
    print msg
    log(msg)

def log(msg, level=logging.INFO):
    """Add a string to the log file."""
    logging.basicConfig(filename=LOG_FILENAME,
                        format='%(asctime)s:%(levelname)s:%(message)s',
                        level=logging.INFO)
    if level == logging.DEBUG:
        logging.debug(msg)
    elif level == logging.INFO:
        logging.info(msg)
    elif level == logging.WARNING:
        logging.warning(msg)
    elif level == logging.ERROR:
        logging.error(msg)
    elif level == logging.CRITICAL:
        logging.critical(msg)
    else:
        raise ValueError(str(level))

def whois(domain, db_con=None):
    """Get WHOIS record as string for domain"""
    rem = cooldown_remaining(domain=domain, db_con=db_con)
    if rem > 0:
        msg = "Domain {0} has {1} seconds remaining on its query cooldown.".format(
            domain, rem)
        print msg
        log(msg)
        raise DomainOnCooldownError()
    else:
        cmd = 'whois {0}'.format(domain)
        return _get_command_result(cmd)

def get_last_whois(domain, db_con=None):
    """Get the last cached copy of the WHOIS record"""
    if db_con is None:
        db_con = db.Datastore()

    return db_con.get_record(domain=domain)

def set_last_whois(domain, record, db_con=None):
    """Set the last cached copy of the WHOIS record"""
    if db_con is None:
        db_con = db.Datastore()

    db_con.set_record(domain=domain, record=record)

def cooldown_remaining(domain, db_con=None):
    """Return # seconds remaining on WHOIS record lookup cooldown"""
    if db_con is None:
        db_con = db.Datastore()

    try:
        return db_con.cooldown_sec_remaining(domain=domain)
    except db.NoWhoisRecordStoredError:
        return NO_COOLDOWN

def print_usage(exit_code=0):
    """Print usage string and quit"""
    print "Usage: python app.py domainlist.txt recipient@example.com"
    sys.exit(exit_code)

def _get_command_result(command):
    return subprocess.check_output(command, stderr=None, shell=True)

def is_domain_name(_str):
    """Is it a domain name?"""
    return re.match(DOMAIN_NAME, _str) is not None

def random_flips(_str):
    """For each character in string, randomly keep val or set to random letter"""
    result = ''
    for index, char in enumerate(list(_str)):
        if index == 0:
            #always modify first character deterministically to ensure that at
            #least one character is always modified
            result = ''.join([result, chr((ord(char) + 1) % 128)])
        else:
            if random.random() < SIMULATE_RANDOMIZE_FREQUENCY:
                result = ''.join([result, chr(random.randrange(65, 125))])
            else:
                result = ''.join([result, char])
    return result

def get_cooldown_sec_from_record(whois_record):
    """Given a WHOIS record retrieved remotely, get cooldown remaining if any

    Returns: int: number of seconds remaining on cooldown or -1 if none
    """
    for line in whois_record.split("\n"):
        for quota_line in WHOIS_LINES_COOLDOWN:
            if re.search(quota_line, line, flags=re.IGNORECASE) is not None:
                match = re.search(r'replenished in (\d+) second', line)
                try:
                    return int(match.group(1))
                except Exception, err:
                    #malformed WHOIS response
                    log(err, level=logging.ERROR)
                    raise

    return NO_COOLDOWN

def get_affected_domain_diffs(recipient, domains, simulate_change,
                              simulate_cooldown, db_con=None):
    """Check the list of domains for WHOIS record changes.

    Args:
        recipient (str): email recipient
        domains (List[str]): List of domains to check
        simulate_change (bool): Whether to simulate a WHOIS record change for
            all domains
        simulate_cooldown (int): Number of seconds to simulate a cooldown for
        db_con (Optional[db.Datastore]): Database connection
    """
    affected_domain_diffs = {}
    for domain in domains:
        if not is_domain_name(domain):
            msg = '{0} is not a valid domain name.'.format(domain)
            log(msg, level=logging.ERROR)
            exit(msg)

        if simulate_cooldown != NO_COOLDOWN:
            msg = ("Simulating cooldown for {0} seconds for all domains "
                   "including {1}.").format(simulate_cooldown, domain)
            print msg
            log(msg, level=logging.INFO)
            send_cooldown_notification(recipient=recipient,
                                       domain=domain,
                                       cooldown_sec=simulate_cooldown)
            try:
                record = db_con.get_record(domain=domain)
                #re-insert the same record but updat the timestamp for last
                #fetched.
                db_con.set_record(domain=domain, record=record)
                db_con.set_cooldown(
                    domain=domain, sec_remaining=simulate_cooldown)
            except db.NoWhoisRecordStoredError:
                msg = ('Tried to set simulated cooldown but no record stored '
                       'for {0}. Will store phony record first and retry.').format(
                           domain)
                print msg
                log(msg, level=logging.INFO)
                record = 'PHONY RECORD'
                db_con.set_record(domain=domain, record=record)
                db_con.set_cooldown(
                    domain=domain, sec_remaining=simulate_cooldown)
            continue

        new = None
        try:
            new = whois(domain, db_con=db_con)
        except DomainOnCooldownError:
            #no new data about this domain available
            continue

        cooldown = get_cooldown_sec_from_record(new)
        if cooldown != NO_COOLDOWN:
            #domain is now on cooldown. will skip until this appears to expire
            msg = ('The quota for queries concerning {0} has been exceeded, '
                   'and the domain is now on cooldown for {1} seconds. An '
                   'alert email will be sent once now to {2}').format(
                       domain, cooldown, recipient)
            print msg
            log(msg, level=logging.WARNING)
            send_cooldown_notification(
                recipient=recipient, domain=domain, cooldown_sec=cooldown)
            try:
                #Note: Good to update record here, but in doing so we also
                #achieve the requirement of updating the last_fetched timestamp.
                db_con.set_record(domain=domain, record=new)
                db_con.set_cooldown(domain=domain, sec_remaining=cooldown)
            except db.NoWhoisRecordStoredError:
                msg = ('Tried to set cooldown but no record stored for {0}. '
                       'Will store record first and retry.').format(domain)
                print msg
                log(msg, level=logging.INFO)
                db_con.set_record(domain=domain, record=new)
                db_con.set_cooldown(domain=domain, sec_remaining=cooldown)
            continue

        cached = ''
        if simulate_change:
            #Simulate a change to WHOIS record by flipping some random
            #characters in the current version of the WHOIS record
            msg = 'Performing simulated modification of WHOIS record for {0}'.format(
                domain)
            print msg
            log(msg)
            cached = random_flips(remove_dynamic_line(new))
        else:
            try:
                cached = get_last_whois(domain=domain, db_con=db_con)
            except NoCachedRecordError:
                set_last_whois(domain=domain, record=new, db_con=db_con)
                log('No previous whois record cached for {0}.'.format(
                    domain))
                continue #no previous record, skip
        diff = get_diff(cached, new)

        #cache for next comparison
        set_last_whois(domain=domain, record=new, db_con=db_con)

        if diff != '':
            affected_domain_diffs[domain] = diff
            log('Whois record for {0} has been modified.'.format(domain))

    return affected_domain_diffs

def _main():
    """Read command line args, check for WHOIS changes, send alerts if any"""
    try:
        domainlist_filename = None
        recipient = None
        simulate_change = False
        simulated_cooldown_sec = NO_COOLDOWN

        if len(sys.argv) == 3:
            domainlist_filename = sys.argv[1]
            recipient = sys.argv[2]
        elif len(sys.argv) == 4:
            if sys.argv[1] != '--simulate_change':
                print_usage(1)
            simulate_change = True
            domainlist_filename = sys.argv[2]
            recipient = sys.argv[3]
        elif len(sys.argv) == 5:
            if sys.argv[1] != '--simulate_cooldown':
                print_usage(1)
            try:
                simulated_cooldown_sec = int(sys.argv[2])
            except ValueError:
                print_usage(1)
            domainlist_filename = sys.argv[3]
            recipient = sys.argv[4]
        else:
            print_usage(1)

        #check for required env variables
        get_env('WHOISALERT_SMTP_USERNAME')
        get_env('WHOISALERT_SMTP_PASSWORD')

        domains = []
        with open(domainlist_filename, 'r') as domainlist:
            for line in domainlist.readlines():
                domains.append(line.strip())

        db_con = db.Datastore()

        affected_domain_diffs = get_affected_domain_diffs(
            recipient=recipient, domains=domains,
            simulate_change=simulate_change,
            simulate_cooldown=simulated_cooldown_sec, db_con=db_con)

        if len(affected_domain_diffs) > 0:
            send_alert(recipient, affected_domain_diffs)
            msg = "Attempted to send alert email after detect changed records."
            log(msg)
            print msg
        else:
            msg = "No changed records found for {0}".format(domains)
            print msg
            log(msg)

    except Exception, err:
        log('Uncaught exception: {0}'.format(str(err)), level=logging.ERROR)
        raise

if __name__ == '__main__':
    _main()
