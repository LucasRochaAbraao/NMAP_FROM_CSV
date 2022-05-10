#!/usr/bin/env python3
import csv
import nmap
import time
import yaml

def scan(hosts:dict, setor:str) -> None:
    """ recebe um dict de hosts no formato:
    {'hostname': 'ip', 'hostname2': 'ip2', ...}, faz a consulta nmap
    nas portas 10050, 10051 e 161, e retorna pro stdout e um arquivo
    csv o resultado."""
    print(f"==> {setor}")

    # Cabeçalho do terminal
    headers = ['HOST (IP)', 'PORTA 10050', 'PORTA 10051', 'PORTA 161'] # zabbix agents and snmp ports
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
                save_to_csv(result=[hostname, ip, port_10050, port_10051, port_161, setor], mode='a')
        else:
            print(f"{hostname} não tem IP cadastrado.")

def get_hosts(hosts_csv:list) -> dict: # [filename.csv, pos_hostname, pos_ip]
    """recebe uma lista obtida do arquivo yaml de configuração contendo
    o nome do arquivo csv, posição do hostname e IP. Extrai essas informações
    do arquivo csv e retorna no formato {chave: valor}."""
    pos_hostname = hosts_csv[1]
    pos_ip = hosts_csv[2]
    with open(file=f'csv/{hosts_csv[0]}', mode='r', encoding='utf-8') as csvfile:
        hosts_reader = csv.reader(csvfile)
        hosts = {row[pos_hostname].strip(): row[pos_ip].strip() for row in hosts_reader} # [hostname, ip]
    return hosts

def save_to_csv(result:list, mode:str) -> None:
    """Apenas uma helper function para facilitar na hora de salvar o resultado."""
    with open(file='resultado.csv', mode=mode) as new_csv_file:
        writer = csv.writer(new_csv_file)
        writer.writerow(result)

if __name__ == '__main__':
    with open('lista_arquivos.yaml') as yaml_file:
        csv_files = yaml.load(stream=yaml_file, Loader=yaml.FullLoader)

    start_time = time.time()

    save_to_csv(result=['hostname', 'ip', 'status_porta_10050', 'status_porta_10051', 'status_porta_161', 'setor'], mode='w')
    for setor, hosts in csv_files['arquivos'].items():
        hosts_csv = get_hosts(hosts)
        print(scan(hosts_csv, setor))

    print(f"--- levou {(time.time() - start_time)/60:.2f} minutos ---")
