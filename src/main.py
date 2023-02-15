import argparse
import csv
import json
import os
import requests
import ipaddress
import datetime
import time
from pprint import pprint
from prettytable import PrettyTable
from src import auth
from src.utils import output, read_file, make_email_text, send_email


class Siem:
    def __init__(self, args):
        api_key = auth.ApiKey()
        self.email_info = {}

        if args.auth:
            api_key.api_key = args.auth
            self.api_key = api_key.api_key
        else:
            self.api_key = api_key.api_key

        # country_code -> country_name
        self.country_mapped_code = {}
        with open('lib/country_code_mapping.csv', 'r') as csv_file:
            rdr = csv.reader(csv_file)
            for line in rdr:
                self.country_mapped_code[line[0]] = line[1]

        self.ip_scan_url = 'https://api.criminalip.io/v1/ip/data'
        self.domain_scan_base_url = 'https://api.criminalip.io/v1/domain'
        self.headers = {
            'x-api-key': self.api_key,
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36,gzip(gfe)',
        }

        if args.email in ['Y', 'y']:
            if os.path.exists('config/.email_info'):
                with open('config/.email_info', 'r') as file:
                    self.email_info = {}
                    lines = file.readlines()

                    for l in lines:
                        k = l.split(':')[0].strip()
                        v = l.split(':')[1].strip()
                        self.email_info[k] = v
            else:
                account = input('Enter email account : ')
                passwd = input('Enter email password : ')
                host = input('Enter email host : ')
                port = input('Enter email port : ')
                send_to = input('Enter email address you want to send to : ')

                with open('config/.email_info', 'w') as file:
                    file.write('account : {}\n'.format(account))
                    file.write('passwd : {}\n'.format(passwd))
                    file.write('host : {}\n'.format(host))
                    file.write('port : {}\n'.format(port))
                    file.write('send_to : {}\n'.format(send_to))

                self.email_info = {
                    'account': account,
                    'passwd': passwd,
                    'host': host,
                    'port': port,
                    'send_to': send_to,
                }
        elif not args.email:
            if os.path.exists('config/.email_info'):
                with open('config/.email_info', 'r') as file:
                    self.email_info = {}
                    lines = file.readlines()

                    for l in lines:
                        k = l.split(':')[0].strip()
                        v = l.split(':')[1].strip()
                        self.email_info[k] = v
            
        if args.ip:
            self.ip_scan(args.ip)
        elif args.domain:
            self.domain_scan(args.domain)
        elif args.ip_file:
            self.file_with_ip_scan(args.ip_file)
        elif args.domain_file:
            self.file_with_domain_scan(args.domain_file)
        elif args.read:
            read_file(args.read)

    def ip_scan(self, ip):
        try:
            ipaddress.ip_address(args.ip)

            if args.cidr:
                splitted_ip = args.ip.split('.')
                args.ip = '{}.{}.{}.0'.format(splitted_ip[0], splitted_ip[1], splitted_ip[2])
        except Exception as e:
            exit(e)

        if args.cidr:
            if int(args.cidr) > 32:
                exit("CIDR must be equal or less than 32")
                
            try:
                args.cidr = int(args.cidr)

                if args.cidr > 32:
                    exit("CIDR must be equal or less than 32")
            except Exception as e:
                exit(e)

            ip_list = ipaddress.ip_network("{}/{}".format(args.ip, args.cidr))
            for ip in ip_list.hosts():
                self.cip_ip_req(ip)
        else:
            self.cip_ip_req(args.ip)

    def file_with_ip_scan(self, file_path):
        ips = []
        with open(file_path, 'r') as file:
            for f in file:
                ips.append(f.strip())

        for d in ips:
            try:
                ipaddress.ip_address(d.split('/')[0])
                ip_base = d.split('/')[0]
                cidr = d.split('/')[1]

                if cidr == '':
                    cidr = None

                if cidr and int(cidr) > 32:
                    cidr = None
                    print("{} : CIDR must be equal or less than 32".format(d))
                    continue
            except IndexError as ie:
                cidr = None

            if cidr:
                splitted_ip = ip_base.split('.')
                ip_base = '{}.{}.{}.0'.format(splitted_ip[0], splitted_ip[1], splitted_ip[2])

                ip_list = ipaddress.ip_network("{}/{}".format(ip_base, cidr))
                for ip in ip_list.hosts():
                    self.cip_ip_req(ip)
            else:
                self.cip_ip_req(ip_base)

    def cip_ip_req(self, ip):
        res = requests.get(url=self.ip_scan_url, params={'ip': ip}, headers=self.headers)
        res = res.json()
        if res['status'] == 200:
            vulns = []
            if res['vulnerability']['count'] > 0:
                for r in res['vulnerability']['data']:
                    vulns.append(r['cve_id'])

            if res['score']['inbound'] == 1:
                score = 'Safe'
            if res['score']['inbound'] == 2:
                score = 'Low'
            if res['score']['inbound'] == 3:
                score = 'Moderate'
            if res['score']['inbound'] == 4:
                score = 'Dangerous'
            if res['score']['inbound'] == 5:
                score = 'Critical'

            country = self.country_mapped_code[res['whois']['data'][0]['org_country_code'].upper()]

            x = PrettyTable()
            x.field_names = ['IP', 'Score', 'AS Name', 'Country', 'Vulns']
            x.add_row([
                res['ip'],
                score,
                res['whois']['data'][0]['as_name'],
                country,
                '\n'.join(vulns)
            ])

            if args.vuln in ['Y', 'y']:
                if vulns:
                    print(x)
            else:
                print(x)

            if vulns:
                ip_risk_data = {
                    'ip': res['ip'],
                    'score': score,
                    'as_name': res['whois']['data'][0]['as_name'],
                    'country': country,
                    'vulns': ', '.join(vulns)
                }

                if self.email_info:
                    subject, email_text = make_email_text('ip', ip_risk_data)
                    send_email(self.email_info, subject, email_text)

            if args.output:
                ret_to_log = {
                    'ip': res['ip'],
                    'score': score,
                    'as_name': res['whois']['data'][0]['as_name'],
                    'country': self.country_mapped_code[res['whois']['data'][0]['org_country_code'].upper()],
                    'vulns': vulns,
                    'scanned_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                output(ret_to_log, 'ip', args.output)

    def domain_scan(self, domain):
        domain_scan_url = '{}/{}'.format(self.domain_scan_base_url, 'reports')
        res = requests.get(url=domain_scan_url, params={'query': domain}, headers=self.headers)
        res = res.json()

        if res['status'] == 200:
            if res['data']['reports']:
                res = sorted(res['data']['reports'], key=lambda x: x['reg_dtime'], reverse=True)

                scan_id = ''
                for r in res:
                    if r['url'] == 'http://{}'.format(domain) or r['url'] == 'https://{}'.format(domain):
                        scan_id = r['scan_id']
                        break

                domain_report_url = '{}/report/{}'.format(self.domain_scan_base_url, scan_id)
                domain_report = requests.get(url=domain_report_url, headers=self.headers)
                domain_report = domain_report.json()

                self.print_domain_scan_result(domain_report, domain)
            else:
                # Start domain scanning

                print("{} is scanning ...".format(args.domain))

                domain_scan_req_url = '{}/scan'.format(self.domain_scan_base_url)
                res = requests.post(url=domain_scan_req_url, data={'query': args.domain}, headers=self.headers)
                res = res.json()

                if res['status'] == 200:
                    scan_id = res['data']['scan_id']

                    retry = 0
                    while True:
                        domain_scan_status_url = '{}/status/{}'.format(self.domain_scan_base_url, scan_id)
                        res = requests.get(url=domain_scan_status_url, headers=self.headers)
                        res = res.json()

                        suc = False
                        if res['status'] == 200:
                            domain_report_url = '{}/report/{}'.format(self.domain_scan_base_url, scan_id)
                            domain_report = requests.get(url=domain_report_url, headers=self.headers)
                            domain_report = domain_report.json()

                            if domain_report['status'] == 200:
                                self.print_domain_scan_result(domain_report, domain)
                                suc = True
                                break

                        if not suc:
                            print('Waiting domain scanning ...')

                            retry += 1
                            if retry > 15:
                                print("{} is not found".format(args.domain))
                                break

                            time.sleep(5)

    def file_with_domain_scan(self, file_path):
        domains = []
        with open(file_path, 'r') as file:
            for f in file:
                domains.append(f.strip())

        for d in domains:
            self.domain_scan(d)

    def print_domain_scan_result(self, report, domain):
        res = report['data']

        vulns = []
        technologies = [tech['name'] for tech in res['technologies']] if res['technologies'] else ''
        for tech in res['technologies']:
            for v in tech['vulner']:
                vulns.append(v)

        ssl = ''
        protocol = ''
        valid_to = ''
        for cert in res['certificates']:
            if domain in cert['subject']:
                ssl = cert['issuer']
                protocol = cert['protocol']
                valid_to = cert['valid_to']

        x = PrettyTable()
        x.field_names = ['Domain', 'Score', 'Technologies', 'Vulns', 'SSL', 'Protocol', 'SSL Expired Date']
        x.add_row([
            res['main_domain_info']['main_domain'],
            res['main_domain_info']['domain_score']['score'].capitalize(),
            '\n'.join(technologies),
            '\n'.join(vulns),
            ssl,
            protocol,
            valid_to
        ])

        if args.vuln in ['Y', 'y']:
            if vulns:
                print(x)
        else:
            print(x)

        if vulns:
            domain_risk_data = {
                'domain': res['main_domain_info']['main_domain'],
                'score': res['main_domain_info']['domain_score']['score'].capitalize(),
                'technologies': ', '.join(technologies),
                'vulns': ', '.join(vulns),
                'ssl': ssl,
                'protocol': protocol,
                'valid_to': valid_to
            }

            if self.email_info:
                subject, email_text = make_email_text('domain', domain_risk_data)
                send_email(self.email_info, subject, email_text)

        if args.output:
            ret_to_log = {
                'domain': res['main_domain_info']['main_domain'],
                'score': res['main_domain_info']['domain_score']['score'].capitalize(),
                'technologies': technologies,
                'vulns': vulns,
                'ssl': ssl,
                'protocol': protocol,
                'ssl_expired_date': valid_to,
                'scanned_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            output(ret_to_log, 'domain', args.output)


parser = argparse.ArgumentParser(description='SherlockSight - by Aidennnn33')
parser.add_argument('-A', '--auth', help='api authentication with a valid criminalip.io api key', metavar='<api_key>')
parser.add_argument('-I', '--ip', help='return information of a target IP', metavar='<ip>')
parser.add_argument('-C', '--cidr', help='input cidr range with IP', metavar='<cidr>')
parser.add_argument('-D', '--domain', help='return information of a target domain', metavar='<domain>')
parser.add_argument('-O', '--output', help='write output to a file', metavar='<path/to/file>')
parser.add_argument('-IF', '--ip-file', help='file with IP or IP/CIDR', metavar='<IP>')
parser.add_argument('-DF', '--domain-file', help='file with domain', metavar='<domain>')
parser.add_argument('-R', '--read', help='read file and pretty print the information', metavar='<path/to/file>')
parser.add_argument('-V', '--vuln', help='return data if IP or Domain info has vulnerabilities', metavar='<Y/N>')
parser.add_argument('-M', '--email', help='send an e-mail if scanner find data with risks', metavar='<Y/N>')


args = parser.parse_args()

