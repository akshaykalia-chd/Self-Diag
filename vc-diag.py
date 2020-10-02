#!/usr/bin/python
import xml.etree.ElementTree as ET
import os
import socket
import ssl
import time
import sys
red = '\033[91m'
green = '\033[32m'
blue = '\033[94m'
cend = '\033[0m'
pyver = sys.version_info[0]

#######################Find IPs and FQDN########################
def find_host_ips(prof_file):
    print("Finding ESXi server IPs using vpxd-profiler.log")
    ips = list()
    cmd = "cat " + prof_file + "| grep /HostStatus/HostId/ | grep IP | awk '{print $3}' | sort -u >/tmp/cmdout.txt"
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    for line in lines:
        line = line.rstrip('\n')
        ips.append(line)
    return ips


def find_DNS_ips(resolv_conf):
    print("Finding DNS server IPs using resolv.conf")
    ips = list()
    file = open(resolv_conf, 'r')
    lines = file.readlines()
    for line in lines:
        if 'nameserver' in line and "127.0.0.1" not in line:
            ips.append((line.split())[1])
    return ips


def find_system_fqdn(vpxd_cfg):
    print("Finding VC FQDN using vpxd.cfg")
    tree = ET.parse(vpxd_cfg)
    root = tree.getroot()
    for vpxdconfig in root.findall('vpxd'):
        return vpxdconfig.find('hostnameUrl').text


def find_system_ip(fqdn):
    print("Finding VC IP using DNS")
    try:
        responce = socket.gethostbyname(fqdn)
        return responce
    except:
        responce = None
        return responce


def get_dgip():
    print("Finding Default Gateway IP")
    cmdout = ">/tmp/cmdout.txt"
    cmd = " route | grep default | awk '{print $2}'" + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    dgip = lines[0].rstrip('\n')
    return dgip


##############Ping Test####################
def ping_host(ip_name, ping_count):
    print("Starting Ping test. Pinging", ip_name)
    i = ping_count
    response_count = 0
    while i != 0:
        if os.name == 'nt':
            response = os.system("ping -n 1 " + ip_name)
        else:
            response = os.system("ping -c 1 " + ip_name)
        response_count = response_count + response
        i = i - 1
    if response_count != 0:
        loss = (response_count / ping_count) * 100
        result = red + 'Ping Test to ' + ip_name + ': Error' + str(loss) + ' % ping packet lost' + cend
    else:
        result = green + 'Ping Test to ' + ip_name + ': Success' + cend
    return result


##############Port Test#################
def port_connect(ip_name, port):
    print("Starting Port Connectivity test for", ip_name, "on Port", port)
    try:
        sok = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sok.connect((ip_name, port))
            result = green + 'Port Connection test:' + ip_name + ':' + str(port) + ' Sucessfull' + cend
            sok.close()
        except:
            result = red + 'Port Connection test:' + ip_name + ':' + str(port) + ' Error' + cend
    except socket.error as err:
        result = red + 'Port Connection test: Socket creation Error Host might be out of ephemeral ports' + cend
    return result


##############DNS lookups #################
def dns_rev_lookup(ip):
    print("Starting Revers Lookup test for", ip)
    try:
        responce = socket.gethostbyaddr(ip)
        message = green + 'DNS lookup for ' + ip + ' Successful, Name is: ' + responce[0] + cend
        return message
    except:
        message = red + 'DNS lookup for ' + ip + ' Failed' + cend
        return message


def dns_fwd_lookup(fqdn):
    print("Starting Forward Lookup test for", fqdn)
    try:
        responce = socket.gethostbyname(fqdn)
        message = green + 'DNS lookup for ' + fqdn + ' Successful, Ip address is: ' + responce + cend
        return message
    except:
        message = red + 'DNS lookup for ' + fqdn + ' Failed' + cend
        return message


##############SSL Connect##################
def get_cert(host, port):
    print("Starting SSL certificate read test. Reading certificate for", host)
    try:
        print(ssl.get_server_certificate((host, port)))
        result = green + 'SSL certificate read test for ' + host + ' : Successful' + cend
        return result
    except:
        result = red + 'SSL certificate read test' + host + ': Error' + cend
        return result


################HB Status##############################
def test_hb(ip):
    print("Starting heartbeat Monitoring")
    cmdout = "/tmp/hbout.txt"
    cmd = "tcpdump -Q in udp port 902 and host " + ip + " -c 6 -w " + cmdout + "&"
    os.system(cmd)
    time.sleep(60)
    cmd = "tcpdump -enr /tmp/hbout.txt | wc -l >/tmp/cmdout.txt"
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    hbcount = int(lines[0].rstrip('\n'))
    if hbcount < 5:
        hbmissed = 6 - hbcount
        result = red + "vCenter server missed heartbeats for " + ip + ". " + str(
            hbmissed) + " heartbeats missed in 60 seconds" + cend
    else:
        result = green + "Host " + ip + ", heartbeat is normal. " + str(
            hbcount) + " heartbeats received in 60 seconds" + cend
    #cmd = "kill -9 $(lsof | grep tcpdump | awk '{print $2}' | sort -u)"
    cmd = "kill -9 $(ps -aux | grep tcpdump | grep -v 'grep' | awk '{print $2}')"
    os.system(cmd)
    return result


def contest_all():
    ports = [443, 80, 902]
    results = list()
    dns_ips = find_DNS_ips("/etc/resolv.conf")
    sys_fqdn = find_system_fqdn("/etc/vmware-vpx/vpxd.cfg")
    sys_ip = find_system_ip(sys_fqdn)
    host_ips = find_host_ips("/var/log/vmware/vpxd/vpxd-profiler-*.log")
    dg_ip = get_dgip()
    results.append(blue + "########Environment Information########" + cend)
    results.append(blue + "DNS IPs:" + str(dns_ips) + cend)
    results.append(blue + "vCenter server Name is:" + sys_fqdn + cend)
    results.append(blue + "vCenter server IP is:" + sys_ip + cend)
    results.append(blue + "Default Gateway IP is:" + dg_ip + cend)
    results.append(blue + "vCenter server is managing host with IPs:" + str(host_ips) + cend)
    results.append("########Test Results########")
    for dns_ip in dns_ips:
        results.append(ping_host(dns_ip, 10))
    results.append(ping_host(dg_ip, 10))
    for host_ip in host_ips:
        results.append(ping_host(host_ip, 10))
    for dns_ip in dns_ips:
        results.append(dns_rev_lookup(dns_ip))
    results.append(dns_rev_lookup(dg_ip))
    for host_ip in host_ips:
        for port in ports:
            results.append(port_connect(host_ip, port))
        results.append(get_cert(host_ip, 443))
        message = dns_rev_lookup(host_ip)
        results.append(message)
        results.append(test_hb(host_ip))
        try:
            host_name = message.split(':')
            host_name = host_name[1]
            host_name = host_name.replace(cend, "")
            host_name = host_name.replace(" ", "")
            results.append(dns_fwd_lookup(host_name))
            for port in ports:
                results.append(port_connect(host_name, port))
            results.append(get_cert(host_name, 443))
        except IndexError:
            message = red + "DNS Reverse Lookup failed for " + host_ip + ". Did not run test using host name" + cend
            results.append(message)
    for result in results:
        print(result)


def contest_one():
    ports = [443, 80, 902]
    results = list()
    if pyver < 3:
        host_ip = raw_input("Enter the IP address of the host:")
    else:
        host_ip = input("Enter the IP address of the host:")

    dns_ips = find_DNS_ips("/etc/resolv.conf")
    sys_fqdn = find_system_fqdn("/etc/vmware-vpx/vpxd.cfg")
    sys_ip = find_system_ip(sys_fqdn)
    host_ips = find_host_ips("/var/log/vmware/vpxd/vpxd-profiler-*.log")
    dg_ip = get_dgip()
    results.append(blue + "########Environment Information########" + cend)
    results.append(blue + "DNS IPs:" + str(dns_ips) + cend)
    results.append(blue + "vCenter server Name is:" + sys_fqdn + cend)
    results.append(blue + "vCenter server IP is:" + sys_ip + cend)
    results.append(blue + "Default Gateway IP is:" + dg_ip + cend)
    results.append(blue + "vCenter server is managing host with IPs:" + str(host_ips) + cend)
    results.append("########Test Results########")
    for dns_ip in dns_ips:
        results.append(ping_host(dns_ip, 10))
    results.append(ping_host(dg_ip, 10))
    results.append(ping_host(host_ip, 10))
    for dns_ip in dns_ips:
        results.append(dns_rev_lookup(dns_ip))
    results.append(dns_rev_lookup(dg_ip))
    message = dns_rev_lookup(host_ip)
    results.append(message)
    for port in ports:
        results.append(port_connect(host_ip, port))
    results.append(get_cert(host_ip, 443))
    results.append(test_hb(host_ip))
    try:
        host_name = message.split(':')
        host_name = host_name[1]
        host_name = host_name.replace(cend, "")
        host_name = host_name.replace(" ", "")
        results.append(dns_fwd_lookup(host_name))
        for port in ports:
            results.append(port_connect(host_name, port))
        results.append(get_cert(host_name, 443))
    except IndexError:
        message = red + "DNS Reverse Lookup failed for " + host_ip + ". Did not run test using host name" + cend
        results.append(message)
    for result in results:
        print(result)


def main():
    options = list()
    options.append("1: Host and vCenter server connectivity")
    options.append("2: VM power operations")
    options.append("3: Snapshot operations")
    options.append("4: Network problem")
    options.append("5: vCenter Server server crash")
    for option in options:
        print(option)
    if pyver < 3:
        choice = int(raw_input("What are you troubleshooting:"))
    else:
        choice = int(input("What are you troubleshooting:"))

    if choice == 1:
        print("a:Test all host")
        print("o:Test one specific host")
        if pyver < 3:
            choice = str(raw_input("How would you like to run this test:"))
        else:
            choice = str(input("How would you like to run this test:"))
        if choice == "a":
            contest_all()
        if choice == "o":
            contest_one()
    else:
        print("Work in progress")

if __name__ == '__main__':
    main()
