import subprocess
import ipaddress
import time
import multiprocessing
import os

ress = {
"rdp": {"good": "Hosts with open RDP", "bad": "Hosts have RDP port open.", "innmap": "yes", "condition": "3389", "state": "open", "message": "no", "additional": "no"},
"smb": {"good": "Hosts with open SMB",  "bad": "Hosts have SMB port open.", "innmap": "yes", "condition": "445", "state": "open", "message": "no", "additional": "ghost"},
"etn": {"good": "Hosts Vulnerable to EternalBlue",  "bad": "Hosts are Vulnerable to EternalBlue.", "innmap": "yes", "condition": "eternalblue", "state": "yes", "message": "   > Vulnerable to EternalBlue!", "additional": "os"},
"ghost": {"good": "Hosts Vulnerable to SMBGhost",  "bad": "Hosts are Vulnerable to SMBGhost.", "innmap": "no"}
}

def parse(key, host, hosts):
    try:
        if ress[key]["innmap"] == "yes" and hosts[host][ress[key]["condition"]] == ress[key]["state"]:
            with open("%s.txt" % key, "a") as f:
                f.write("%s\n" % host)
            if ress[key]["message"] != "no":
                print(ress[key]["message"])
            if ress[key]["additional"] == "os":
                try:
                    print('   >%s' % hosts[host]["os"])
                except:
                    pass
            elif ress[key]["additional"] == "ghost":
                try:
                    if IsTargetVulnerable(host, 445):
                        with open("ghost.txt", "a") as f:
                            f.write("%s\n" % host)
                        print("   > Vulnerable to SMBGhost!")
                except:
                    pass
    except KeyError:
        pass

def parallel_routes(routes):
    while True:
        x = len(routes)
        for i in routes:
            if int(i.split('/')[1]) < 24:
                c = list(ipaddress.ip_network(i).subnets())
                routes.append(str(ipaddress.IPv4Network(c[0])))
                routes.append(str(ipaddress.IPv4Network(c[1])))
                routes.remove(i)
        if x == len(routes):
            break
    return routes

def clear_subnets(ips):
    while True:
        c = len(ips)
        for i in ips:
            for b in ips:
                if i != b and ipaddress.ip_network(i).subnet_of(ipaddress.ip_network(b)):
                    ips.remove(i)
        if c == len(ips):
            break
    return ips

def scan(ip):
    hosts = {}
    for line in str(subprocess.Popen('nmap --open -PE -T5 -p445,3389 --script smb-vuln-ms17-010 --script smb-os-discovery %s' % ip, stdout=subprocess.PIPE).stdout.read()).split('\\r\\n'):
        if line.startswith('Nmap scan report for '):
            if line.count('(') == 1 and line.count(')') == 1:
                hosts.update({line.split('(')[1].replace(')', '') : {'ResolvedName' : line.split(' ')[4]}})
                host = line.split('(')[1].replace(')', '')
            else:
                hosts.update({line.split(' ')[4] : {'ResolvedName' : ''}})
                host = line.split(' ')[4]
        elif line.startswith('445/tcp'):
            hosts[host].update({'445' : 'open'})
        elif line.startswith('3389/tcp'):
            hosts[host].update({'3389' : 'open'})
        elif line.count('smb-vuln-ms17-010') == 1:
            hosts[host].update({'eternalblue' : 'yes'})
        elif line.count(' OS: ') == 1:
            hosts[host].update({'os' : line.split(':')[1]})
    for host in hosts:
        if hosts[host]['ResolvedName'] != '':
            print('%s (%s)' % (host, hosts[host]['ResolvedName']))
        else:
            print(host)
        for i in ress:
            parse(i, host, hosts)

def parse_res(var, string1, string2):
    try:
        with open("%s.txt" % var, 'r') as file:
            tempvar = file.readlines()
        string = "[+] %s (%s):" % (string1, len(tempvar))
        for i in tempvar:
            string+='%s, ' % i.replace('\n', '')
        print(string[:string.rfind(',')])
    except:
        print("[-] 0 %s" % string2)

def get_routes(routes):
    diaps = []
    ro = False
    for i in str(routes).split('\\r\\n'):
        if i.count('.') >= 9 and ro == True:
            s = i.split(' ')
            while s.count('') != 0:
                s.remove('')
            if s[1] != '255.255.255.255' and s[1] != '240.0.0.0' and s[0] != '0.0.0.0' and s[1] != '0.0.0.0' and s[0] != '127.0.0.0' and diaps.count(str(ipaddress.IPv4Network('%s/%s' % (s[0], s[1]), False))) == 0 and s[0].startswith('169.') == False and s[0].startswith('10.212.134') == False:
                diaps.append(str(ipaddress.IPv4Network('%s/%s' % (s[0], s[1]), False)))
        elif ro == False and i.count('IPv4 Route Table') == 1:
            ro = True
    return diaps, routes

if __name__ == "__main__":
    try:
        print("[%s][!] Parsing default routes ..." % time.strftime("%H:%M:%S", time.localtime()))
        default_routes, default_data = get_routes(str(subprocess.check_output("route print -4")))
        old_data = default_data
        for i in default_routes:
            print('   > %s' % i)
        while True:
            print("[%s][*] Waiting for route changes ..." % time.strftime("%H:%M:%S", time.localtime()))
            time.sleep(1)
            routes, new_data = get_routes(str(subprocess.check_output("route print -4")))
            if new_data != old_data:
                if default_data == new_data:
                    print("[%s][!] Default route configuration restored!" % time.strftime("%H:%M:%S", time.localtime()))
                    old_data = default_data
                elif default_routes == routes:
                    print("[%s][-] Changes detected, but no new routes added!" % time.strftime("%H:%M:%S", time.localtime()))
                    old_data = default_data
                elif default_routes != routes:
                    print("[%s][+] Changes detected, following routes added:" % time.strftime("%H:%M:%S", time.localtime()))
                    for i in default_routes:
                        routes.remove(i)
                    routes = clear_subnets(routes)
                    for i in ress:
                        try:
                            os.remove('%s.txt' % i)
                        except:
                            pass
                    for i in routes:
                        print('   > %s' % i)
                    routes = parallel_routes(routes)
                    if len(routes) == 1:
                        print("[%s][+] Launching single-threaded scan against %s ..." % (time.strftime("%H:%M:%S", time.localtime()), routes[0]))
                        scan(routes[0])
                    else:
                        if len(routes) < 60:
                            threads =  len(routes)
                        else:
                            threads = 60
                        print("[%s][+] Launching multithreader scan ..."  % time.strftime("%H:%M:%S", time.localtime()))
                        with multiprocessing.Pool(threads) as p:
                            p.map(scan, routes)
                    for i in ress:
                        parse_res(i, ress[i]["good"], ress[i]["bad"])
                    old_data = new_data
    except KeyboardInterrupt:
        print("User interrupted!\t\t\t\t\t")
