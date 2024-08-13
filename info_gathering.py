import whois
import dns.resolver
import argparse
import shodan
import socket
import requests
from colorama import init, Fore
# it will show how to use this tool in this block of code.
init()
red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN
reset = Fore.RESET

argparse = argparse.ArgumentParser(description="this is a basic information gathering tool",
                                   usage="python3 info_gathering.py -d DOMAIN [-s IP]")

argparse.add_argument("-d", "--domain", help="Enter the domain name (ex: -d example.com)", required=True)
argparse.add_argument("-s", "--shodan", help="Enter the Ip for shodan search (ex: -s 192.0.0.0)")
argparse.add_argument("-o", "--outfile", help="Enter the file to write output (ex: -o save.txt)")

args = argparse.parse_args()
domain = args.domain
ip = args.shodan
outfile = args.outfile

# whois module
print(f"{red}[-] Getting whois info...{reset}")
whois_result = ' '
# using whois library
try:
    w = whois.whois(domain)
    print(w)
    print("[+] whois info found....):")
    whois_result += "[+] Name: {}".format(w.domain_name) + '\n'
    whois_result += "[+] Registrar: {}".format(w.registrar) + '\n'
    whois_result += "[+] Whois_server: {}".format(w.whois_server) + '\n'
    whois_result += "[+] Updated_date: {}".format(w.updated_date) + '\n'
    whois_result += "[+] Creation_date: {}".format(w.creation_date) + '\n'
    whois_result += "[+] Expiration_date: {}".format(w.expiration_date) + '\n'
    whois_result += "[+] Name_servers: {}".format(w.name_servers) + '\n'
    whois_result += "[+] Emails: {}".format(w.emails) + '\n'
    whois_result += "[+] Country: {}".format(w.country) + '\n'
    whois_result += "[+] Org: {}".format(w.org) + '\n'
    whois_result += "[+] Address: {}".format(w.address) + '\n'
except:
    pass
print(whois_result)
# Dns module
print(f" {red}[-] Getting Dns info ....{reset}")
dns_result = ' '

try:
    for a in dns.resolver.resolve(domain, 'A'):
        dns_result += "[+] A record: {}".format(a.to_text()) + '\n'

    for ns in dns.resolver.resolve(domain, 'NS'):
        dns_result += "[+] NS record: {}".format(ns.to_text()) + '\n'

    for txt in dns.resolver.resolve(domain, 'TXT'):
        dns_result += "[+] TXT record: {}".format(txt.to_text()) + '\n'

    for mx in dns.resolver.resolve(domain, 'mx'):
        dns_result += "[+] mx record: {}".format(mx.to_text()) + '\n'

    for AAAA in dns.resolver.resolve(domain, 'AAAA'):
        dns_result += "[+] AAAA record: {}".format(AAAA.to_text()) + '\n'

    for cname in dns.resolver.resolve(domain, 'CNAME'):
        dns_result += "[+] Cname record: {}".format(cname.to_text()) + '\n'

except:
    pass
print(dns_result)

# Geolocation module
print(f"{red}[-] Getting Geolocation info....{reset}")
geo_result = ' '

try:
    response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    geo_result += "[+] Country_code: {}".format(response["country_code"]) + '\n'
    geo_result += "[+] Country_name: {}".format(response["country_name"]) + '\n'
    geo_result += "[+] City: {}".format(response["city"]) + '\n'
    geo_result += "[+] State: {}".format(response["state"]) + '\n'
    geo_result += "[+] longitude: {}".format(response["longitude"]) + '\n'
    geo_result += "[+] latitude: {}".format(response["latitude"]) + '\n'
    geo_result += "[+] IPv4: {}".format(response["IPv4"]) + '\n'
    geo_result += "[+] Postal: {}".format(response["Postal"]) + '\n'

except:
    pass
print(geo_result)
#  shodan module
shodan_outfile = ' '
if ip:
    print(f" {red}[-] Getting info from shodan for ip {ip} {reset}")
    api = shodan.Shodan('wt98at2r5pLw8aSd26OSjunaFdC22wR6')
    try:
        results = api.search(ip)
        print("[+] Result found : {}".format(results['total']))
        for result in results['matches']:
            shodan_outfile += "[+] IP : {}".format(result['ip_str']) + '\n'
            shodan_outfile += "[+] Data : {}".format(result['data']) + '\n'
            print(' ')
    except:
        print("[-] Shodan Search not found...")
        print(shodan_outfile)

if(outfile):
    with open(outfile,'w') as file:
        file.write(f"{red}[+] Who is result start from here {reset}" + "\n \n")
        file.write(whois_result + '\n\n')
        file.write(f" {red}[+] Dns result start from here {reset}" + "\n \n")
        file.write(dns_result + '\n\n')
        file.write(f"{red}[+] Geolocation result start from here{reset}" + "\n \n")
        file.write(geo_result + '\n\n')
        file.write(f"{red}[+] Shodan result start from here{reset}" + "\n \n")
        file.write(shodan_outfile + '\n\n')