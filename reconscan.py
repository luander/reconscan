#!/usr/bin/env python
"""
###############################################################################################################
## [Title]: reconscan.py -- a recon/enumeration script
## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
##-------------------------------------------------------------------------------------------------------------
## [Details]: 
## This script is intended to be executed remotely against a list of IPs to enumerate discovered services such 
## as smb, smtp, snmp, ftp and other. 
##-------------------------------------------------------------------------------------------------------------
## [Warning]:
## This script comes as-is with no promise of functionality or accuracy.  I strictly wrote it for personal use
## I have no plans to maintain updates, I did not write it to be efficient and in some cases you may find the 
## functions may not produce the desired results so use at your own risk/discretion. I wrote this script to 
## target machines in a lab environment so please only use it against systems for which you have permission!!  
##-------------------------------------------------------------------------------------------------------------   
## [Modification, Distribution, and Attribution]:
## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
## author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's 
## worth anything anyway :)
###############################################################################################################
"""
import argparse

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import sys
import time
import xml.etree.ElementTree as et


def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip, port))
    jobs.append(p)
    p.start()
    return


def dnsEnum(ip_address, port):
    print "INFO: Detected DNS on " + ip_address + ":" + port
    if port.strip() == "53":
        SCRIPT = "./dnsrecon.py %s" % (ip_address) # execute the python script
        subprocess.call(SCRIPT, shell=True)
    return


def httpEnum(ip_address, port):
    cwd = os.getcwd()
    print "INFO: Detected http on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
    HTTPSCAN = "nmap -sV -Pn -vv -p " + port + " --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN " + cwd + "/" + ip_address + "_http.nmap " + ip_address
    results = subprocess.check_output(HTTPSCAN, shell=True)
    # DIRBUST = "./dirbust.py http://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    # subprocess.call(DIRBUST, shell=True)
    print "INFO: Performing Nikto scan for " + ip_address + ":" + port
    NIKTOSCAN = "nikto -host %s -p %s > %s.nikto" % (ip_address, port, ip_address)
    results = subprocess.check_output(NIKTOSCAN, shell=True)
    return


def httpsEnum(ip_address, port):
    cwd = os.getcwd()
    print "INFO: Detected https on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
    HTTPSCANS = "nmap -sV -Pn -vv -p " + port + " --script=ssl-heartbleed,sslv2,ssl-poodle,http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oX " + cwd + "/" + ip_address + "_https.nmap " + ip_address
    results = subprocess.check_output(HTTPSCANS, shell=True)
    DIRBUST = "./dirbust.py https://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    #NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return


def mssqlEnum(ip_address, port):
    cwd = os.getcwd()
    print "INFO: Detected MS-SQL on " + ip_address + ":" + port
    print "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port    
    MSSQLSCAN = "nmap -vv -sV -Pn -p " + port + " --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oX " + cwd + "/" + ip_address + "_mssql.xml " + ip_address
    results = subprocess.check_output(MSSQLSCAN, shell=True)


def sshEnum(ip_address, port):
    print "INFO: Detected SSH on " + ip_address + ":" + port
    SCRIPT = "./sshrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return


def snmpEnum(ip_address, port):
    cwd = os.getcwd()
    print "INFO: Detected snmp on " + ip_address + ":" + port
    ONESIXONESCAN = "onesixtyone %s" % (ip_address)
    results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()

    if results != "":
        if "Windows" in results:
            results = results.split("Software: ")[1]
            snmpdetect = 1
        elif "Linux" in results:
            results = results.split("[public] ")[1]
            snmpdetect = 1
        if snmpdetect == 1:
            print "[*] SNMP running on " + ip_address + "; OS Detect: " + results
            SNMPWALK = "snmpwalk -c public -v1 %s 1 > results/%s_snmpwalk.txt" % (ip_address, ip_address)
            results = subprocess.check_output(SNMPWALK, shell=True)

    NMAPSCAN = "nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes -oX " + cwd + "/" + ip_address + "_snmp.nmap " + ip_address
    results = subprocess.check_output(NMAPSCAN, shell=True)
    resultsfile = "results/" + ip_address + "_snmprecon.txt"
    f = open(resultsfile, "w")
    f.write(results)
    f.close
    # SCRIPT = "./snmprecon.py %s" % (ip_address)
    # subprocess.call(SCRIPT, shell=True)
    return


def smtpEnum(ip_address, port):
    print "INFO: Detected smtp on " + ip_address + ":" + port
    if port.strip() == "25":
        SCRIPT = "./smtprecon.py %s" % (ip_address)       
        subprocess.call(SCRIPT, shell=True)
    else:
        print "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)" 
    return


def smbEnum(ip_address, port):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    if port.strip() == "445":
        SCRIPT = "./smbrecon.py %s 2>/dev/null" % (ip_address)
        subprocess.call(SCRIPT, shell=True)
    return


def ftpEnum(ip_address, port):
    print "INFO: Detected ftp on " + ip_address + ":" + port
    SCRIPT = "./ftprecon.py %s %s" % (ip_address, port)       
    subprocess.call(SCRIPT, shell=True)
    return


def nmapScan(ip_address):
    cwd = os.getcwd()
    ip_address = ip_address.strip()
    print "INFO: Running general TCP/UDP nmap scans for " + ip_address
    serv_dict = {}
    TCPSCAN = "nmap -vv -Pn -A -sC -sS -T 4 -p- -oN '" + cwd + "/" + ip_address + ".nmap' -oX '" + cwd + "/" + ip_address + "_nmap_scan_import.xml' " + ip_address
    results = subprocess.check_output(TCPSCAN, shell=True)

    # UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '" + cwd + "/" + ip_address + "U.nmap' -oX '" + cwd + "/" + ip_address + "U_nmap_scan_import.xml' " + ip_address
    # results = subprocess.check_output(UDPSCAN, shell=True)

    # parse nmap generated xml to discover ports and services
    try:
        root = et.parse(cwd + "/" + ip_address + "_nmap_scan_import.xml")
        ports_tag = root.find('host/ports')
        output_data = []

        # for each <port>...</port>
        for port in ports_tag:
            ports = []
            if port.tag == 'port':
                state = port.find('state')
                # check if port is open
                if state is not None and state.get('state') == 'open':
                    service = port.find('service')

                    # get service type running in port
                    if service is not None:
                        serv_name = service.get('name')
                        if serv_name in serv_dict:
                            ports = serv_dict[serv_name]

                        # fill dictionary with service type and ports
                        # {'service':[22,23,24], ...}
                        product = service.get('product') if service.get('product') is not None else "?"
                        output_data.append([port.get('portid'), serv_name, product])
                        ports.append(port.get('portid'))
                        serv_dict[serv_name] = ports
        # print nice columns to output:
        widths = [max(map(len, col)) for col in zip(*output_data)]
        for row in output_data:
            print "  ".join((val.ljust(width) for val, width in zip(row, widths)))

    except Exception as e:
        print e
        return

    print serv_dict
    # go through the service dictionary to call additional targeted enumeration functions 
    for serv in serv_dict: 
        ports = serv_dict[serv]

        if serv == "http":
            for port in ports:
                multProc(httpEnum, ip_address, port)
        elif (serv == "ssl/http") or ("https" in serv):
            for port in ports:
                multProc(httpsEnum, ip_address, port)
        # elif "ssh" in serv:
        #     for port in ports:
        #         port = port.split("/")[0]
        #         multProc(sshEnum, ip_address, port)
        # elif "smtp" in serv:
        #     for port in ports:
        #         port = port.split("/")[0]
        #         multProc(smtpEnum, ip_address, port)
        elif "snmp" in serv:
            for port in ports:
                multProc(snmpEnum, ip_address, port)
        # elif "domain" in serv:
        #     for port in ports:
        #         port = port.split("/")[0]
        #         multProc(dnsEnum, ip_address, port)
        # elif "ftp" in serv:
        #     for port in ports:
        #         port = port.split("/")[0]
        #         multProc(ftpEnum, ip_address, port)
        elif "microsoft-ds" in serv:
            for port in ports:
                multProc(smbEnum, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                multProc(httpEnum, ip_address, port)

    print "INFO: TCP/UDP Nmap scans completed for " + ip_address 
    return


def main():
    parser = argparse.ArgumentParser(description="""
############################################################
####                      RECON SCAN                    ####
####            A multi-process service scanner         ####
####        http, ftp, dns, ssh, snmp, smtp, ms-sql     ####
############################################################
    """)
    parser.add_argument('-ip', '--ip', action='store', dest='ip')
    parser.add_argument('-f', '--file', action='store', dest='file')
    args = parser.parse_args()
    ips = []
    if args.ip:
        ips.append(args.ip)
    elif args.file:
        if os.path.isfile(args.file):
            for ip in open(args.file).readlines():
                    ips.append(ip)
        else:
            exit("File not found")

    jobs = []
    for ip in ips:
        p = Process(target=nmapScan, args=(ip,))
        jobs.append(p)
        p.start()

if __name__=='__main__':
    main()
