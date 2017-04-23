"""Send an email alert when the whois record for a domain changes.

Usage:

    $ python app.py [--simulate_change] [--simulate_cooldown n] domainlist.txt recipientlist.csv

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
import csv

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

SUPPORTED_CHANNELS = ('email', 'email_simulated_file')

SIMULATED_SENDER_EMAIL = 'simulated_sender@example.com'

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

def get_smtp_auth_env(smtp_auth):
    """Get SMTP auth parameters from env variables as neded."""
    if 'username' not in smtp_auth:
        smtp_auth['username'] = get_env('WHOISALERT_SMTP_USERNAME')
    if 'password' not in smtp_auth:
        smtp_auth['password'] = get_env('WHOISALERT_SMTP_PASSWORD')
    if 'server' not in smtp_auth:
        smtp_auth['server'] = get_env('WHOISALERT_SMTP_SERVER', use_default=True)
    if 'port' not in smtp_auth:
        smtp_auth['port'] = get_env('WHOISALERT_SMTP_PORT', use_default=True)

    return smtp_auth

def send_cooldown_notification(recipients, domain, cooldown_sec):
    """Send email alerting that domain is on cooldown for WHOIS lookups

    Args:
        recipients (tuple[str, str]): A list of recipient tuples, each
            containing the destination address and the communciation channel.
        domain (str)
        cooldown_sec (int)
    """
    smtp_auth = dict()
    subject = 'INFO: WHOIS queries for {0} are on cooldown for {1} second(s)'.format(
        domain, str(cooldown_sec))
    body = ("WHOIS records cannot be retrieved for {0} for {1} more second(s). "
            "This is your only notification during this period. Consider "
            "querying less often for the affected domain to avoid blind "
            "periods.\n").format(domain, cooldown_sec)
    for recipient_tuple in recipients:
        assert len(recipient_tuple) == 2
        recipient = recipient_tuple[0]
        channel = recipient_tuple[1]
        assert channel in SUPPORTED_CHANNELS
        simulate = bool(channel == 'email_simulated_file')
        if not simulate:
            smtp_auth = get_smtp_auth_env(smtp_auth)
        send_email(smtp_auth, recipient, subject, body, simulate=simulate)

def send_alert(recipients, affected_domain_diffs):
    """Send email alert

    Args:
        recipients (tuple[str, str]): A list of recipient tuples, each
            containing the destination address and the communciation channel.
        affected_domain_diffs (dict): Maps domain names whose WHOIS records
            have changed to the diff strings. {'example.com' => '---...'}
    """
    smtp_auth = dict()

    subject = 'ALERT: Modified WHOIS record for: '
    subject += ', '.join(sorted(affected_domain_diffs.keys()))

    body = ''
    for domain in affected_domain_diffs.keys():
        body = ''.join([body, "{0}:\n\n".format(domain)])
        body = ''.join([body, affected_domain_diffs[domain], "\n\n"])

    for recipient_tuple in recipients:
        assert len(recipient_tuple) == 2
        recipient = recipient_tuple[0]
        channel = recipient_tuple[1]
        assert channel in SUPPORTED_CHANNELS
        simulate = bool(channel == 'email_simulated_file')
        if not simulate:
            smtp_auth = get_smtp_auth_env(smtp_auth)
        send_email(smtp_auth, recipient, subject, body, simulate=simulate)

def send_email(smtp_auth, recipient, subject, body, simulate=False):
    """Send email via SMTP.
    Args:
        smtp_auth (dict): Contains 'username' (str), 'password' (str),
            'server' (str), and 'port' (int)
        recipient (str): The email address to send to, or the filepath to write
            the email contents to if `simulate` is True.
        subject (str)
        body (str)
        simulate (bool): If specified, instead of sending an email via SMTP
            server, this will be simulated and the email will be written to the
            filepath specified in the `recipient` argument.

    Reference:
    http://stackoverflow.com/questions/10147455/trying-to-send-email-gmail-as-mail-provider-using-python
    """
    email_to = [recipient]

    if simulate:
        smtp_auth['username'] = SIMULATED_SENDER_EMAIL

    #Sending message, first construct actual message
    message = ("From: %s\nTo: %s\nSubject: %s\n\n%s" %
               (smtp_auth['username'], ", ".join(email_to), subject, body))

    if simulate:
        with open(recipient, 'a') as sim:
            sim.write(message)

        print "Simulated email wrote to '{0}'".format(recipient)
        return
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
    print("Usage: python app.py [--simulate_change] [--simulate_cooldown n] "
          "domainlist.txt recipientlist.csv")
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

def simulate_cooldown_domain(simulate_cooldown, domain, recipients, db_con):
    """Simulate a cooldown for the specified domain"""

    msg = ("Simulating cooldown for {0} seconds for all domains "
           "including {1}.").format(simulate_cooldown, domain)
    print msg
    log(msg, level=logging.INFO)
    send_cooldown_notification(recipients=recipients,
                               domain=domain,
                               cooldown_sec=simulate_cooldown)
    record = ''
    try:
        record = db_con.get_record(domain=domain)
    except db.NoWhoisRecordStoredError:
        msg = ('Tried to set simulated cooldown but no record stored '
               'for {0}. Will store phony record first and retry.').format(
                   domain)
        print msg
        log(msg, level=logging.INFO)
        record = 'PHONY RECORD'

    #even if the record is not a phony one, we still need to call
    #set_record in order to update the timestamp this domain was last
    #fetched.
    db_con.set_record(domain=domain, record=record)
    db_con.set_cooldown(
        domain=domain, sec_remaining=simulate_cooldown)

def get_simulated_cached_record(domain, db_con):
    """Simulate a change to the WHOIS record of the specified domain

    For the sake of unit testing purposes, this will try to avoid making a
    network query to the WHOIS server and grab a cached version from the
    database first.

    Returns: Cached version of WHOIS record to diff against
    """
    #Simulate a change to WHOIS record by flipping some random
    #characters in the current version of the WHOIS record
    msg = 'Performing simulated modification of WHOIS record for {0}'.format(
        domain)
    print msg
    log(msg)

    try:
        return get_last_whois(domain=domain, db_con=db_con)
    except NoCachedRecordError:
        msg = ("No previous whois record cached for {0}, but we are "
               "simulating a change to that record. We will therefore "
               "fetch the new record and randomly alter that one.").format(domain)
        print msg
        log(msg)
        #we may end up fetching for a domain that is on cooldown here,
        #but that's unlikely as there ought to be a cached record for
        #that domain in this case. Even if not, it's not a big deal;
        #we'll just get some complaints about the domain being on
        #cooldown and randomly modify that, and this will still suffice
        #for the purposes of simulating a WHOIS record change.
        return whois(domain, db_con=db_con)

def handle_domain_on_cooldown(domain, cooldown, recipients, new, db_con):
    """Send out notifications and update db to reflect cooldown"""

    msg = ('The quota for queries concerning {0} has been exceeded, '
           'and the domain is now on cooldown for {1} seconds. An '
           'alert email will be sent once now to: {2}').format(
               domain, cooldown, [rpt[0] for rpt in recipients])
    print msg
    log(msg, level=logging.WARNING)
    send_cooldown_notification(
        recipients=recipients, domain=domain, cooldown_sec=cooldown)
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

def get_affected_domain_diffs(recipients, domains, simulate_change,
                              simulate_cooldown, db_con=None):
    """Check the list of domains for WHOIS record changes.

    Args:
        recipients (tuple[str, str]): A list of recipient tuples, each
            containing the destination address and the communciation channel.
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

        if simulate_cooldown > 0:
            simulate_cooldown_domain(simulate_cooldown=simulate_cooldown,
                                     domain=domain,
                                     recipients=recipients,
                                     db_con=db_con)
            continue

        cached = ''
        if simulate_change:
            #simulated change to WHOIS record only

            cooldown = cooldown_remaining(domain=domain, db_con=db_con)
            if cooldown > 0:
                msg =('Simulating a change to WHOIS record for domain {0}, but '
                      'this domain is currently on cooldown. Skipping.').format(domain)
                print msg
                log(msg)
                continue
            else:
                cached = get_simulated_cached_record(domain=domain, db_con=db_con)
                new = random_flips(remove_dynamic_line(cached))
        else:
            #normal, non-simulated operation
            try:
                new = whois(domain, db_con=db_con)
            except DomainOnCooldownError:
                #no new data about this domain available
                continue

            try:
                cached = get_last_whois(domain=domain, db_con=db_con)
            except NoCachedRecordError:
                set_last_whois(domain=domain, record=new, db_con=db_con)
                log('No previous whois record cached for {0}.'.format(
                    domain))
                continue #no previous record, skip

        cooldown = get_cooldown_sec_from_record(new)
        if cooldown > 0:
            #domain is now on cooldown. will skip until this appears to expire
            handle_domain_on_cooldown(domain=domain,
                                      cooldown=cooldown,
                                      recipients=recipients,
                                      new=new,
                                      db_con=db_con)
            continue

        diff = get_diff(cached, new)

        #cache for next comparison
        set_last_whois(domain=domain, record=new, db_con=db_con)

        if diff != '':
            affected_domain_diffs[domain] = diff
            log('Whois record for {0} has been modified.'.format(domain))

    return affected_domain_diffs

def get_recipients(recipients_filename):
    """Get list of recipients and comm channels from file"""
    recipients = []
    with open(recipients_filename, 'r') as recipientlist:
        reader = csv.reader(recipientlist)

        for recipient in reader:
            addr = recipient[0]
            channel = recipient[1]
            if channel not in SUPPORTED_CHANNELS:
                raise ValueError("Only email is supported as an alert channel!")
            recipients.append((addr, channel))

    return recipients

def main(argv, db_con=None, check_env=True):
    """Read command line args, check for WHOIS changes, send alerts if any

    Args:
        argv: e.g. sys.argv
        db_con: Datastore
        check_env: If True (default), SMTP cred env variables will be checked.
    """
    try:
        domainlist_filename = None
        recipients_filename = None
        simulate_change = False
        simulated_cooldown_sec = NO_COOLDOWN

        if len(argv) == 3:
            domainlist_filename = argv[1]
            recipients_filename = argv[2]
        elif len(argv) == 4:
            if argv[1] != '--simulate_change':
                print_usage(1)
            simulate_change = True
            domainlist_filename = argv[2]
            recipients_filename = argv[3]
        elif len(argv) == 5:
            if argv[1] != '--simulate_cooldown':
                print_usage(1)
            try:
                simulated_cooldown_sec = int(argv[2])
            except ValueError:
                print_usage(1)
            domainlist_filename = argv[3]
            recipients_filename = argv[4]
        else:
            print_usage(1)

        if check_env:
            #check for required env variables
            get_env('WHOISALERT_SMTP_USERNAME')
            get_env('WHOISALERT_SMTP_PASSWORD')

        domains = []
        with open(domainlist_filename, 'r') as domainlist:
            for line in domainlist.readlines():
                domains.append(line.strip())

        recipients = get_recipients(recipients_filename)

        if db_con is None:
            db_con = db.Datastore()

        affected_domain_diffs = get_affected_domain_diffs(
            recipients=recipients, domains=domains,
            simulate_change=simulate_change,
            simulate_cooldown=simulated_cooldown_sec, db_con=db_con)

        if len(affected_domain_diffs) > 0:
            send_alert(recipients=recipients,
                       affected_domain_diffs=affected_domain_diffs)
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
    main(sys.argv)
