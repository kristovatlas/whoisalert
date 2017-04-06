"""Send an email alert when the whois record for a domain changes.

Usage:

    $ python app.py [--simulate] domainlist.txt recipient@example.com

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

LOG_FILENAME = 'whoisalert.log'
DEFAULT_SMTP_SERVER = 'smtp.gmail.com'
DEFAULT_SMTP_PORT = 465

DEFAULT_MAP = {'WHOISALERT_SMTP_SERVER': DEFAULT_SMTP_SERVER,
               'WHOISALERT_SMTP_PORT': DEFAULT_SMTP_PORT}

DOMAIN_NAME = r'^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$'

SIMULATE_RANDOMIZE_FREQUENCY = 0.05

class NoCachedRecordError(Exception):
    """No previous WHOIS record cached for this domain"""
    pass

def remove_dynamic_line(whois_record):
    """Remove the line from the record that changes per query"""
    result = ''
    for line in whois_record.split("\n"):
        #print "DEBUG: remove_dynamic_line: line=%s" % line
        #this line changes per query and should be ignored
        if re.search('Last update of WHOIS database', line, flags=re.IGNORECASE) is None:
            if result == '':
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

def get_whois_cache_filename(domain):
    """Get the filename used to store last seen WHIOS record"""
    return ''.join([domain, '.txt'])

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

def whois(domain):
    """Get WHOIS record as string for domain"""
    cmd = 'whois {0}'.format(domain)
    return _get_command_result(cmd)

def get_last_whois(domain):
    """Get the last cached copy of the WHOIS record"""
    filename = get_whois_cache_filename(domain)
    if not os.path.isfile(filename):
        raise NoCachedRecordError()

    with open(filename, 'r') as whois_cached:
        return whois_cached.read()

def set_last_whois(domain, record):
    """Set the last cached copy of the WHOIS record"""
    filename = get_whois_cache_filename(domain)
    with open(filename, 'w') as whois_cached:
        whois_cached.write(record)

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

def get_affected_domain_diffs(domains, simulate):
    """Check the list of domains for WHOIS record changes."""
    affected_domain_diffs = {}
    for domain in domains:
        if not is_domain_name(domain):
            msg = '{0} is not a valid domain name.'.format(domain)
            log(msg, level=logging.ERROR)
            exit(msg)

        new = whois(domain)
        cached = ''
        if simulate:
            #Simulate a change to WHOIS record by flipping some random
            #characters in the current version of the WHOIS record
            log('Performing simulated modification of WHOIS record for {0}'.format(
                domain))
            cached = random_flips(remove_dynamic_line(new))
        else:
            try:
                cached = get_last_whois(domain)
            except NoCachedRecordError:
                set_last_whois(domain, new)
                log('No previous whois record cached for {0}.'.format(
                    domain))
                continue #no previous record, skip
        diff = get_diff(cached, new)
        set_last_whois(domain, new) #cache for next comparison
        if diff != '':
            affected_domain_diffs[domain] = diff
            log('Whois record for {0} has been modified.'.format(domain))

    return affected_domain_diffs

def _main():
    """Read command line args, check for WHOIS changes, send alerts if any"""
    try:
        domainlist_filename = None
        recipient = None
        simulate = False

        if len(sys.argv) == 3:
            domainlist_filename = sys.argv[1]
            recipient = sys.argv[2]
        elif len(sys.argv) == 4:
            if sys.argv[1] != '--simulate':
                print_usage(1)
            simulate = True
            domainlist_filename = sys.argv[2]
            recipient = sys.argv[3]
        else:
            print_usage(1)

        #check for required env variables
        get_env('WHOISALERT_SMTP_USERNAME')
        get_env('WHOISALERT_SMTP_PASSWORD')

        domains = []
        with open(domainlist_filename, 'r') as domainlist:
            for line in domainlist.readlines():
                domains.append(line.strip())

        affected_domain_diffs = get_affected_domain_diffs(domains, simulate)

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
        log('Uncaught exception: {0}'.format(err), level=logging.ERROR)

if __name__ == '__main__':
    _main()
