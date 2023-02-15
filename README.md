
# Introduction  
siem_the_nightowl is a code that reports IP addresses and Domain's CVE vulnerabilities, certificates, and risk scores. Registering mail information sends a security check mail when a vbulnerability is found. This program uses Criminal IP's API, and this site has 10k credits available monthly.  
  
  
# Prerequisites  
  
* [criminalip.io](https://www.criminalip.io) API Key  
  
  
  
# Installation  
  
Clone repository:  
  
```  
$ git clone https://github.com/Jaxon1111/siem_the_nightowl.git  
```  
  
```  
$ cd siem_the_nightowl  
```  
  
```  
$ python3 -m venv .venv  
$ source .venv/bin/activate  
```  
  
```  
$ pip3 install -r requirements.txt  
```  
  
  
  
# Getting started  
  
```  
$ chmod +x siem_the_nightowl 
```  
  
```  
$ ./siem_the_nightowl --auth [your-criminalip-api-key]  
```  
  
  
  
# Optional Arguments  
  
| Flag | MetaVar | Usage |  
| --------------------- | -------------------- | ------------------------------------------------------------ |  
| `-A/--auth` | **API key** | api authentication with a valid [criminalip.io](http://criminalip.io/) api key |  
| `-I/--ip` | **IP** | return information of a target IP |  
| `-C/--cidr` | **Cidr** | text search query |  
| `-D/--domain` | **Domain** | return information of a target domain |  
| `-O/--output` | **File Path** | write output to a file |  
| `-IF / --ip-file` | **IP File Path** | file with IP or IP/CIDR |  
| `-DF / --domain-file` | **Domain File Path** | file with domain |  
| `-R / --read` | **File Path** | read file and pretty print the information |  
| `-V / --vuln` | **Y/N** | return data if IP or Domain info has vulnerabilities |  
| `-M / --email` | **Y/N** | send an e-mail if scanner find data with risks |  
  
(ex)  
$ ./siem_the_nightowl -A api_key  
$ ./siem_the_nightowl -I 1.1.1.1 -O log.txt  
$ ./siem_the_nightowl -I 1.1.1.1 -C 24 -O log.txt  
$ ./siem_the_nightowl -D google.com -O log.txt  
$ ./siem_the_nightowl -IF sample_ip.txt  
$ ./siem_the_nightowl -DF sample_domain.txt  
$ ./siem_the_nightowl -I 1.1.1.1 -C 24  
$ ./siem_the_nightowl -R log/ip_log.txt  
$ ./siem_the_nightowl -M Y  
  
  
# Issue / Feedback etc.  
  
If you have any issues/feedback you want to tell me, please feel free to contact me!  
  
You're always welcome to add a sameple pull request added to example_quiries.py.
