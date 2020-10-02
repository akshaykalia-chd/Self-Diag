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

##############Hostd State##################
def get_hostd_status():
    print("Checking hostd status")
    error = False
    cmdout = ">/tmp/cmdout.txt"
    cmd = "/etc/init.d/hostd status"
    cmd = cmd + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    hostdstatus = lines[0].rstrip('\n')
    cmdout = ">/tmp/cmdout.txt &"
    cmd = "esxcli network ip route ipv4 list"
    cmd = cmd + cmdout
    os.system(cmd)
    time.sleep(10)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    if len(lines) != 0:
        for line in lines:
            if "Connection failed" in line:
                error = True
    else:
        error = True
    if error:
        if "hostd is not running." in hostdstatus:
            result = red + "hostd is not running." + cend
        else:
            result = red + "hostd is running. However, it is either hung or still initializing" + cend
    else:
        result = green + "hostd is running" + cend

    return result


##############vpxa State##################
def get_vpxa_status():
    print("Checking vpxa status")
    cmdout = ">/tmp/cmdout.txt"
    cmd = "/etc/init.d/vpxa status "
    cmd = cmd + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    if "vpxa is running" in lines[0].rstrip('\n'):
        return green + lines[0].rstrip('\n') + cend
    else:
        return red + lines[0].rstrip('\n') + cend


###############Get hostd and vpxa pids##############
def get_pids():
    print("Finding vpxa and hostd Pids")
    result = list()
    cmdout = ">/tmp/cmdout.txt"
    cmd = "vmkvsitools lsof |grep "
    cmd = cmd + '"/bin/hostd"'
    cmd = cmd + "| awk '{print $1,$2}' | sort -u"
    cmd = cmd + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    hostd_pids = list()
    for line in lines:
        line = line.rstrip('\n')
        if 'hostdCgiServer' not in line:
            pid = line.split()
            hostd_pids.append(pid[0])
    if len(hostd_pids) > 1:
        message = red + 'Error: Multiple Pids detected for hostd' + str(hostd_pids) + cend
        result.append(message)
    else:
        message = green + 'hostd Pid is:' + hostd_pids[0] + cend
        result.append(message)

    cmd = "vmkvsitools lsof |grep "
    cmd = cmd + '"/usr/lib/vmware/vpxa/bin/vpxa"'
    cmd = cmd + "| awk '{print $1,$2}' | sort -u"
    cmd = cmd + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    vpxa_pids = list()
    for line in lines:
        line = line.rstrip('\n')
        pid = line.split()
        vpxa_pids.append(pid[0])
    if len(vpxa_pids) > 1:
        message = red + 'Error: Multiple Pids detected for vpxa' + str(vpxa_pids) + cend
        result.append(message)
    else:
        message = green + 'vpxa Pid is:' + vpxa_pids[0] + cend
        result.append(message)
    return result


################HB Status##############################
def test_hb(vmk_int, vc_ip):
    print("Starting heartbeat Monitoring")
    cmdout = "/tmp/hbout.txt"
    cmd = "pktcap-uw --vmk "
    cmd = cmd + vmk_int
    cmd = cmd + " --dstip " + vc_ip
    cmd = cmd + " --proto 0x11 -p 902 -o " + cmdout + " -c 6 &"
    os.system(cmd)
    time.sleep(60)
    cmd = "tcpdump-uw -enr" + " /tmp/hbout.txt" + "|wc -l" + ">/tmp/cmdout.txt"
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    hbcount = int(lines[0].rstrip('\n'))
    if hbcount < 5:
        hbmissed = 6 - hbcount
        result = red + "Host missed sending heartbeats. " + str(hbmissed) + " heartbeats missed in 60 seconds" + cend
    else:
        result = green + "Host heartbeat is normal " + str(hbcount) + " heartbeats sent in 60 seconds" + cend
    cmd = "kill -9 $(lsof | grep pktcap-uw |awk '{print $1}' | sort -u)"
    os.system(cmd)
    return result


####################Find Managment VMK interface############################
def find_vmk_int(vmk_ip):
    cmdout = ">/tmp/cmdout.txt"
    cmd = " esxcfg-vmknic -l | grep "
    cmd = cmd + vmk_ip
    cmd = cmd + "| awk '{print $1}'"
    cmd = cmd + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    vmk_int = lines[0].rstrip('\n')
    return vmk_int


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
    print(" Starting Revers Lookup test for", ip)
    result = list()
    try:
        responce = socket.gethostbyaddr(ip)
        result.append(responce[0])
        message = green + 'DNS lookup for ' + ip + ' Successful, Name is: ' + responce[0] + cend
        result.append(message)
        return result
    except:
        result.append('Lookup Failed')
        message = red + 'DNS lookup for ' + ip + ' Failed' + cend
        result.append(message)
        return result


def dns_fwd_lookup(fqdn):
    print("Starting Forward Lookup test for", fqdn)
    try:
        responce = socket.gethostbyname(fqdn)
        message = green + 'DNS lookup for ' + fqdn + ' Successful, Ip address is: ' + responce + cend
        return message
    except:
        message = red + 'DNS lookup for ' + fqdn + ' Failed' + cend
        return message


##############Find Ips for vCenter server, ESXi, DNS servers, Default Gateway#################
def find_ips(vpxa_cfg):
    print("Finding host and VC IP using vpxa.cfg")
    tree = ET.parse(vpxa_cfg)
    root = tree.getroot()
    ips = list()
    for vpxaconfig in root.findall('vpxa'):
        vcenter_ip = vpxaconfig.find('serverIp').text
        host_ip = vpxaconfig.find('hostIp').text
    ips.append('vCenter server IP is:' + vcenter_ip)
    ips.append('ESXi management IP is:' + host_ip)
    return ips


def find_DNS_ips(myfile):
    print("Finding DNS server IPs using resolv.conf")
    ips = list()
    file = open(myfile, 'r')
    lines = file.readlines()
    for line in lines:
        if 'nameserver' in line:
            ips.append((line.split())[1])
    return ips


def get_dgip():
    print("Finding Default Gateway IP")
    cmdout = ">/tmp/cmdout.txt"
    cmd = "localcli network ip route ipv4 list | grep default | awk '{print $3}'" + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    dgip = lines[0].rstrip('\n')
    dgip = 'Default Gateway IP is:' + dgip
    return dgip


######################Phy Nic Ops#########################################
def find_mgmt_nic(vmk_int):
    cmdout = ">/tmp/cmdout.txt"
    cmd = "net-stats -l | grep "
    cmd = cmd + '"' + vmk_int
    cmd = cmd + '"' + "|awk " + "'{print $6"
    cmd = cmd + '"," $1 ","$4}'
    cmd = cmd + "'| awk -F"
    cmd = cmd + '"," '
    cmd = cmd + "'{print $3}'" + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    portset = lines[0].rstrip('\n')
    cmdout = ">/tmp/cmdout.txt"
    cmd = "net-stats -l | grep "
    cmd = cmd + '"' + vmk_int
    cmd = cmd + '"' + "|awk " + "'{print $6"
    cmd = cmd + '"," $1 ","$4}'
    cmd = cmd + "'| awk -F"
    cmd = cmd + '"," '
    cmd = cmd + "'{print $2}'" + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    portid = lines[0].rstrip('\n')
    cmd = "vsish -e cat net/portsets/" + portset + "/ports/" + portid + "/schedTeamUplink" + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    phy_int = lines[0].rstrip('\n')
    return phy_int


def mon_mgmt_nic(phy_int):
    i = 10
    count = 0
    error = False
    while i >= 0:
        i = i - 1
        cmdout = ">/tmp/cmdout.txt"
        cmd = "localcli network nic get --nic-name " + phy_int + " | grep -E "
        cmd = cmd + '"Link Status" ' + "| awk -F: "
        cmd = cmd + "'{print $2}' " + cmdout
        os.system(cmd)
        file = open('/tmp/cmdout.txt', 'r')
        lines = file.readlines()
        file.close()
        lines = lines[0].rstrip('\n')
        time.sleep(10)
        if "Up" not in lines:
            error = True
            count = count + 1
    if error:
        message = red + "Link State for " + phy_int + " Not stable. Link was down " + str(
            count) + " times in 100 seconds" + cend
        return message
    else:
        message = green + "Link State for " + phy_int + " is stable" + cend
        return message


############Function to call  Host and vCenter server connectivity  tests#############################
def host_con():
    results = list()
    ips = find_ips('/etc/vmware/vpxa/vpxa.cfg')
    dns_ips = find_DNS_ips('/etc/resolv.conf')
    vc_ip = ips[0].split(':')
    vc_ip = vc_ip[1]
    host_ip = ips[1].split(':')
    host_ip = host_ip[1]
    dgip = get_dgip()
    vmk_int = find_vmk_int(host_ip)
    phy_int = find_mgmt_nic(vmk_int)
    results.append(blue + "########Environment Information########" + cend)
    results.append(blue + ips[0] + cend)
    results.append(blue + ips[1] + cend)
    results.append(blue + 'DNS IPs:' + str(dns_ips) + blue)
    results.append(blue + dgip + cend)
    results.append(blue + 'Management VMkernel Interface:' + vmk_int + cend)
    results.append(blue + 'Management Traffic Physical Interface:' + phy_int + cend)
    rev_lookup_vc = dns_rev_lookup(vc_ip)
    rev_lookup_host = dns_rev_lookup(host_ip)
    if rev_lookup_vc[0] != "Lookup Failed":
        message = blue + "vCenter server Name is:" + rev_lookup_vc[0] + cend
        results.append(message)
    if rev_lookup_host[0] != "Lookup Failed":
        message = blue + "Esxi server Name is:" + rev_lookup_host[0] + cend
        results.append(message)

    results.append("########Test Results########")

    for dns_ip in dns_ips:
        results.append(ping_host(dns_ip, 10))
    results.append(ping_host(vc_ip, 10))
    dgip = dgip.split(':')
    results.append(ping_host(dgip[1], 10))

    if rev_lookup_vc[0] != "Lookup Failed":
        results.append(rev_lookup_vc[1])
        results.append(dns_fwd_lookup(rev_lookup_vc[0]))
    if rev_lookup_host[0] != "Lookup Failed":
        results.append(rev_lookup_host[1])
        results.append(dns_fwd_lookup(rev_lookup_host[0]))

    results.append(port_connect(vc_ip, 443))
    results.append(port_connect(vc_ip, 80))
    results.append(port_connect(host_ip, 80))
    results.append(port_connect(host_ip, 443))
    if rev_lookup_vc[0] != "Lookup Failed":
        results.append(port_connect(rev_lookup_vc[0], 80))
        results.append(port_connect(rev_lookup_vc[0], 443))
    else:
        results.append(rev_lookup_vc[1])

    if rev_lookup_host[0] != "Lookup Failed":
        results.append(port_connect(rev_lookup_host[0], 80))
        results.append(port_connect(rev_lookup_host[0], 443))
    else:
        results.append(rev_lookup_host[1])
    results.append(get_cert(rev_lookup_vc[0], 443))
    results.append(get_cert(rev_lookup_host[0], 443))
    results.append(get_hostd_status())
    results.append(get_vpxa_status())
    for pids in get_pids():
        results.append(pids)
    results.append(test_hb(vmk_int, vc_ip))
    results.append(mon_mgmt_nic(phy_int))
    for result in results:
        print(result)


###############File lock test##########################
def lock_state(filepath):
    cmdout = ">/tmp/cmdout.txt"
    cmd = "vmfsfilelockinfo -p " + '"' + filepath + '" ' + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    for line in lines:
        if "not locked by any ESX" in line or "host having mac address" in line:
            return line


###############Function to find host Nic MACs##########################
def prep_mac_list():
    print("Preparing Physical Nic MAC list")
    mac_list = list()
    cmdout = ">/tmp/cmdout.txt"
    cmd = "localcli network nic list" + cmdout
    os.system(cmd)
    file = open('/tmp/cmdout.txt', 'r')
    lines = file.readlines()
    file.close()
    for line in lines:
        line = line.rstrip('\n')
        line = line.split()
        if "vmnic" in line[0]:
            mac_list.append(line[7])
    return mac_list


###############Function to find vmx path##########################
def find_vmx_path(vmname):
    print("Finding vmx path for", vmname)
    tree = ET.parse("/etc/vmware/hostd/vmInventory.xml")
    root = tree.getroot()
    vmx_path = list()
    for vm in root.findall('ConfigEntry'):
        if vmname in vm.find('vmxCfgPath').text:
            vmx_path.append(vm.find('vmxCfgPath').text)
    if len(vmx_path) > 1:
        print(red + "Cannot continue, more than one VMs found with given name. Please be more specific" + cend)
    else:
        try:
            return vmx_path[0]
        except IndexError:
            print(red + "Cannot continue, VMs not found with given name. Please be more specific" + cend)
            exit()


def find_vm_files(vmx_path, mac_list):
    vmx_lock_state = lock_state(vmx_path)
    vmx_home = find_vm_home(vmx_path)
    can_continue = False
    if "not locked by any ESX" in vmx_lock_state:
        can_continue = True
    else:
        for mac in mac_list:
            if mac in vmx_lock_state:
                can_continue = True
    if can_continue:
        files = os.listdir(vmx_home)
        file_paths = list()
        for file in files:
            file = vmx_home + "/" + file
            file_paths.append(file)
        cmdout = ">/tmp/cmdout.txt"
        cmd = "cat " + vmx_path + " | grep vmdk" + cmdout
        os.system(cmd)
        file = open('/tmp/cmdout.txt', 'r')
        lines = file.readlines()
        file.close()
        vmdk_list = list()
        for line in lines:
            line = line.rstrip('\n')
            line = line.split('=')
            line = line[1].replace('"', '')
            line = line.replace(' ', '')
            vmdk_list.append(line)
        for vmdk in vmdk_list:
            cmdout = " >/tmp/cmdout.txt"
            vmdk_path = '"' + vmx_home + "/" + vmdk + '"'
            cmd = "vmkfstools -qv 10 " + vmdk_path + cmdout
            os.system(cmd)
            file = open('/tmp/cmdout.txt', 'r')
            lines = file.readlines()
            file.close()
            for line in lines:
                if "open successful" in line:
                    line = line.split(':')
                    line = line[1]
                    line = line.replace('"', '')
                    line = line.replace(' ', '')
                    file_paths.append(line)
        unique_file_paths = list()
        for file_path in file_paths:
            if file_path not in unique_file_paths:
                unique_file_paths.append(file_path)
        return unique_file_paths

    else:
        mac = vmx_lock_state.split('[')[1].replace(']', '')
        message = red + "vmx file of the VM is locked. Please run the script on host with MAC " + mac + cend
        return message


def find_vm_home(vmx_path):
    vm_home = vmx_path.split('/')
    vm_home.pop()
    tmp = ""
    for ele in vm_home:
        if ele != '':
            tmp = tmp + "/" + ele
    return tmp


def lock_split(file_lock_states, mac_list):
    mac_list1 = list()
    locks_split = False
    file_lock_states_not_none = filter(None.__ne__, file_lock_states)
    for file_lock_state in file_lock_states_not_none:
        if "host having mac address" in file_lock_state:
            mac = file_lock_state.split('[')[1].replace(']', '')
            mac = mac.rstrip('\n')
            mac = mac.strip("'")
            if mac not in mac_list:
                locks_split = True
                mac_list1.append(mac)
    if locks_split:
        message = red + "VMs file are locked by Remote host or multiple hosts." + "Files are locked by hosts with mac " + str(
            mac_list1) + cend
        return message
    else:
        message = green + "No file lock split detected" + cend
        return message


############Function to call  VM power operations  tests#############################
def vm_power():
    if pyver < 3:
        vmname = raw_input("Enter the name of VM that is not working:")
    else:
        vmname = input("Enter the name of VM that is not working:")
    vmname = vmname
    mac_list = prep_mac_list()
    vmx_path = find_vmx_path(vmname)
    vm_files = find_vm_files(vmx_path, mac_list)
    file_lock_states = list()
    for vm_file in vm_files:
        file_lock_states.append(lock_state(vm_file))
    results = list()
    ips = find_ips('/etc/vmware/vpxa/vpxa.cfg')
    dns_ips = find_DNS_ips('/etc/resolv.conf')
    host_ip = ips[1].split(':')
    host_ip = host_ip[1]
    dgip = get_dgip()
    vmk_int = find_vmk_int(host_ip)
    phy_int = find_mgmt_nic(vmk_int)
    results.append(blue + "########Environment Information########" + cend)
    results.append(blue + ips[0] + cend)
    results.append(blue + ips[1] + cend)
    results.append(blue + 'DNS IPs:' + str(dns_ips) + blue)
    results.append(blue + dgip + cend)
    results.append(blue + 'Management VMkernel Interface:' + vmk_int + cend)
    results.append(blue + 'Management Traffic Physical Interface:' + phy_int + cend)
    results.append(blue + 'Local host MACs:' + str(mac_list) + cend)
    results.append("########Test Results########")
    results.append(lock_split(file_lock_states, mac_list))
    for result in results:
        print(result)

def main():
    options = list()
    options.append("1: Host and vCenter server connectivity")
    options.append("2: VM power operations")
    options.append("3: Snapshot operations")
    options.append("4: Network problem")
    options.append("5: Storage problem")
    for option in options:
        print(option)
    if pyver < 3:
        choice = int(raw_input("What are you troubleshooting:"))
    else:
        choice = int(input("What are you troubleshooting:"))
    if choice == 1:
        host_con()
    if choice == 2:
        vm_power()
    else:
        print("Work in progress")


if __name__ == '__main__':
    main()
