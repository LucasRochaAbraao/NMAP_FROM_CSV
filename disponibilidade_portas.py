import csv
import nmap
import time
import yaml # PyYAML


def scan(hosts):
    # espera uma lista de hosts:
    # [[hostname, ip], [hostname2, ip2], [hostname3, ip3]...]

    headers = ['HOST', 'PORTA 10050', 'PORTA 10051', 'PORTA 161'] # zabbix agents and snmp ports
    print("{0:^40}|{1:^15}|{2:^15}|{3:^15}".format(*headers))

    nmScan = nmap.PortScanner()
    for hostname, ip in hosts.items():
        if ip:
            scan_result = nmScan.scan(ip, ports='10050,10051,161')
            if scan_result['nmap']['scanstats']['downhosts'] == '1':
                print(f"* Nmap não conseguiu escanear o host {hostname}({ip}).")
            else:
                try: port_10050 = scan_result['scan'][ip]['tcp'][10050]['state']
                except: port_10050 = 'Sem retorno'

                try: port_10051 = scan_result['scan'][ip]['tcp'][10051]['state']
                except: port_10051 = 'Sem retorno'

                try: port_161 = scan_result['scan'][ip]['tcp'][161]['state']
                except: port_161 = 'Sem retorno'

                hostname_ip = f"{hostname[:22]} ({ip})"

                print(f"{hostname_ip:^40} {port_10050:^15} {port_10051:^15} {port_161:^15}")
        else:
            print(f"{hostname} não tem IP cadastrado.")

def get_hosts(hosts_csv): # [filename.csv, pos_hostname, pos_ip]
    pos_hostname = hosts_csv[1]
    pos_ip = hosts_csv[2]
    with open(file=f'csv/{hosts_csv[0]}', mode='r', encoding='utf-8') as csvfile:
        hosts_reader = csv.reader(csvfile)
        hosts = {row[pos_hostname]: row[pos_ip] for row in hosts_reader} # [hostname, ip]
    return hosts

if __name__ == '__main__':
    with open('lista_arquivos.yaml') as yaml_file:
        csv_files = yaml.load(yaml_file, Loader=yaml.FullLoader)

    start_time = time.time()

    for categoria, hosts in csv_files['arquivos'].items():
        print(f"==> {categoria}")
        hosts_csv = get_hosts(hosts)
        print(scan(hosts_csv))

    print(f"--- levou {(time.time() - start_time)/60:.2f} minutos ---")
