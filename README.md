# NMAP_FROM_CSV
Esse script lê arquivos CSV para escanear via nmap, com ajuda de um arquivo de configuração yaml para listar o nome dos arquivos csv e a posição do hostname e IP dentro deles, permitindo usar arquivos sem padrão ou formatação específica.

Atualmente, o script está consultando portas específicas para validar a comunicação do zabbix server com zabbix agents em diversos dispositivos. Ao finalizar, é possível executar um outro script para cadastrar todos hosts que validamos possuem comunicação com o server.
Também é possível alterar essas portas para sua demanda, ou receber as portas como argumentos CLI.

### Instalação e execução
Baixe o repositorio e instale os pacotes.
```
pip install -r requirements.txt
```
- Mude o nome do arquivo lista_arquivos_sample.yaml para lista_arquivos.yaml
- Coloque as informações de servidores mantendo a formatação do arquivo.
- Coloque seu arquivo csv na pasta csv/.
  
Por último, mude a permissão do script e execute.
```
sudo chmod +x validar_portas.py
./validar_portas.py
```