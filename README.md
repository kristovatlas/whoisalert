# whoisalert

Provide a list of domains and get an alert when WHOIS records for any of those
domains changes.

## Usage

    $ python app.py [--simulate] domainlist.txt recipient@example.com

Expects the following environment variables set:

 * WHOISALERT_SMTP_USERNAME
 * WHOISALERT_SMTP_PASSWORD
 * WHOISALERT_SMTP_SERVER (Optional: Defaults to 'smtp.gmail.com')
 * WHOISALERT_SMTP_PORT (Optional: Defaults to 465)

The `--simulate` option simulates an change to the WHOIS record so you can verify
that your alert system is working correctly

## Requirements

 * whois -- (Command-line application) Internet domain name and network number directory service (MacOS: `brew install whois`)

## Sample Output

```
$ python app.py domainlist.txt myemail@example.com
No changed records found for ['google.com', 'yahoo.com', 'blockchain.info']
```

```
$ python app.py --simulate domainlist.txt myemail@example.com
Email sent to myemail@example.com.
Attempted to send alert email after detect changed records.
```

Sample email generated:

![Sample email generated](sample_mail.png)
