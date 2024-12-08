#!/bin/bash

clear

#define color 
red='\e[1;31m'
green='\e[1;32m'
blue='\e[1;34m'
blink='\e[5m'
stop_blink='\e[25m'
stop_color='\e[0m'


echo -e "$red**********************************************************************$stop_color"
echo -e  """ $green  
 _____ __   _ _______  _____         ______ _______ _______ _     _ _______  ______ _____ __   _  ______
   |   | \  | |______ |     |       |  ____ |_____|    |    |_____| |______ |_____/   |   | \  | |  ____
 __|__ |  \_| |       |_____| _____ |_____| |     |    |    |     | |______ |    \_ __|__ |  \_| |_____|

------------------------------------------------------------------------------------
                                                        Crafted by sidharth
                                                        Twitter: kidnapshadow_kd
------------------------------------------------------------------------------------
 $stop_color """

echo -e "$red**********************************************************************$stop_color"


echo -e "Getting Things Ready For You..... :) \n"

apt-get install python3

apt-get install python3-pip

pip3 install socket

pip3 install whois

pip3 install dns.resolver

pip3 install shodan

pip3 install colorama

pip3 install threading

pip3 install requests

pip3 install argparse

chmod +x info_gathering.py

cp info_gathering.py /usr/bin/info_gathering.py

echo -e "\ndone...\n"

clear

python3 info_gathering.py --help