#!/usr/bin/python

__author__ = "BaelTD"
__copyright__ = "Copyright 2019, ScanYLife"
__credits__ = ["David Morelli"]
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "BaelTD"
__email__ = "morelli.d14@gmail.com"
__status__ = "Production"

import sys
import os
import nmap

def sexScan (ipSexAddr): 
	scan_Successfully = None;
	print("SCAN IN PROGRESS...")
	nm = nmap.PortScanner()
	print("!!SCAN MIGHT SEVERAL MINUTE!!")
	print("!!SCAN MIGHT SEVERAL MINUTE!!")
	print("!!SCAN MIGHT SEVERAL MINUTE!!")	
	nm.scan(hosts=ipSexAddr, arguments='-O -F -sS --osscan_guess')
	scan_Successfully = nm
	print("SCAN SUCCESSFULLY...")
	for host in nm.all_hosts():
		print("-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.-.-.-.-.-.-.-.-")
		print("HOST: "+nm[host].hostname())
    		print("IP: "+host)
		if 'mac' in nm[host]['addresses']:
			print("MAC: "+str(nm[host]['addresses']['mac']))
#  		print(nm[host].get('addresses'))
		
	return scan_Successfully

def onlyUP(ip,port):
	scan_Up = None;

	
	return scan_Up


if __name__ == '__main__' :
	sexNmapScan = None;
	print("-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.-.-.-.-.-.-.-.-")
	print("-.-.-.-.-.-.-.-.-.-.-..-.-.SCANYLIFE-.-.-.-.-.--.-.-.-.-.-.-.-.-")
	print("-.-.-.-.-.-.-.-.-.-.-.-.SCANYLIFE-.-.-.-.--.-.-.-.-.-.-.-.--.-.-")
	print("-.-.-.-.-.-.-.-.-.-.-SCANYLIFE-.-.-.-.--.-.-.-.-.-.-.-.-.-.-.-.-")
	print("-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.-.-.-.-.-.-.-.-.-.-.-")
	sex = raw_input("Insert IP CLASS INDEX (192.168.1.1/24 == ALL NET): ")

	if sex != "":
		sexNmapScan = sexScan(sex)
	else: 
		print("NO IP INSERT")
		print("RESTART PROGRAM")
	print("-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.-.-.-.-.-.-.-.-")
	print("-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.-.-.-.-.-.-.-.-")
	print("-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.-.-.-.-.-.-.-.-")
	exit(0)
	
