import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pprint import pprint


def output(result, target, file_path):
    if target == 'ip':
        file_path = "log/ip_{}".format(file_path)
    elif target == 'domain':
        file_path = "log/domain_{}".format(file_path)

    with open(file_path, "a") as file:
        file.write("{}\n".format(json.dumps(result)))
        file.close()

def read_file(file_name):
    with open("{}".format(file_name), "r") as file:
        for r in file:
            pprint(json.loads(r))
            print("")


def send_email(email_info, subject, email_text):
    # SMTP
    smtp = smtplib.SMTP(email_info['host'], email_info['port'])
    smtp.ehlo()
    smtp.starttls()
    smtp.login(email_info['account'], email_info['passwd'])

    email_text = MIMEText(email_text, _charset='utf-8')

    # send email
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['To'] = email_info['send_to'] 
    msg.attach(email_text)

    try:
        smtp.sendmail(email_info['account'], email_info['send_to'], msg.as_string())
        return True
    except Exception as e:
        print(e)
        return False
    finally:
        smtp.quit()


def make_email_text(target, data):
    if target == 'ip':
        subject = '[Criminal IP Report] IP Risk has been found'
        email_text = '''
IP : {}

Score : {}

AS Name : {}

Country : {}

Vulnerabilities : {}
'''.format(
    data['ip'],
    data['score'],
    data['as_name'],
    data['country'],
    data['vulns']
)

    if target == 'domain':
        subject = '[Criminal IP Report] Domain Risk has been found'
        email_text = '''
Domain : {}

Score : {}

Technologies : {}

Vulnerabilities : {}

SSL : {}

Protocol : {}

SSL Expired Date : {}
'''.format(
    data['domain'],
    data['score'],
    data['technologies'],
    data['vulns'],
    data['ssl'],
    data['protocol'],
    data['valid_to'],
)

    return subject, email_text
