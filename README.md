# information_gathering
This is a basic information gathering tool made with python
In this tool we have
1. Getting whois info.
   For Getting whois result we import a package called whois
3. Getting DNS info.
    For Getting whois result we import a package called dns.resolver
5. Getting Geolocation info. and last
    For Getting whois result we import a package called requests
7. getting shodan info.
    For Getting whois result we import a package called shodan

# Requirment
import whois
import dns.resolver
import argparse
import shodan
import socket
import requests
from colorama import init, Fore

# usages
python3 info_gathering.py -h {to get help}
python3 info_gathering.py -d DOMAIN [-s IP]
example:- python3 info_gathering.py -d facebook.com -o [outfile] -s [ip]





