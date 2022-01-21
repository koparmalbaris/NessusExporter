#!/usr/bin/python
# -*- coding:utf-8 -*-

"""
################
README

İlgili python scripti çalıştırılmadan önce, config.txt dosyası içerisine:

  - access = Nessus'dan alınan AccessKey girilmeli
  - secret = Nessus'dan alınan SecretKey girilmeli
  - url = Nessus'un çalışmakta olduğu URL adresi girilmeli
  - scan_id = Çıktısı alınmak istenen zafiyet taramasının Scan ID değeri girilmeli

Scriptin çalıştırılabilmesi için:

  - python3 NessusExporter.py

Authors

  # https://github.com/koparmalbaris
  # https://github.com/ahmtcnn

################
"""

import requests
import json
from six.moves import configparser

# Nessusa bağlantı sağlanırken oluşan "Unverified HTTPS Request" hatasını bypasslamak için:
# Hatanın çıkma sebebi Nessus'un SSL sertifikası üzerinde çalışması
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Nessus API adresinden dönen zafiyetlerin seviyelendirmeleri "0,1,2,3,4" olarak dönüyordu.
# Bu sebep ile global değişkenler tanımlanarak .JSON çıktısında ilgili zafiyet seviyelerinin Information, Low, Medium... ile çıkmasını sağlamak için:
severities = {
  0:'Informational',
  1:'Low',
  2:'Medium',
  3:'High',
  4:'Critical'
}

# Nessus API adreslerine gerekli GET veya POST isteklerini atmak için:
def get(destination):
  return requests.get("{}/{}".format(base_url, destination),
                      verify  = False,
                      headers = {"X-ApiKeys": "accessKey={}; secretKey={}".format(access_key, secret_key)})

def post(destination, data):
  return requests.post("{}/{}".format(base_url, destination),
                       verify  = False,
                       headers = {"X-ApiKeys": "accessKey={}; secretKey={}".format(access_key, secret_key)},
                       data    = data)

# Nessus'un "scan/scan_id/hosts/host_id" API adresine atılan istekten dönen verileri parse ederk her bir host hakkında bilgileri almak için: 
# Aynı zamanda her bir isteğin cevabını daha sonra kullanmak üzere kaydetmek için:
def set_extended_output(hosts,scan_id):
  extended_output = []
  hosts_response_list = []
  for host in hosts:
    extended_obj = {}
    extended_obj['hostname'] = host['hostname']
    host_id = host['host_id']

    response = get("scans/{}/hosts/{}".format(scan_id,host_id,))
    hosts_response_list.append(response)
    json_response = json.loads(response.text)

    try:
      extended_obj['operating_system'] = json_response['info']['operating-system']
    except:
      extended_obj['operating_system'] = None
    extended_obj['host-ip'] = json_response['info']['host-ip']
    extended_output.append(extended_obj)
  
  return extended_output, hosts_response_list

# Nessus'un "scan/scan_id" API adresine atılan istekten dönen verileri parse ederek daha önce her bir hosts için kaydedilen response'lar ile karşılaştırarak "Affected Hostları" belirlemek için:
def set_output(json_data,hosts_response_list):
  outputs = []
  # Vulnerabilities API'sine istek atıp veriler arasından bize gerekli olan objeleri seçmek için:
  vulnerabilities = json_data['vulnerabilities']

  for vulnerability in vulnerabilities:
    obj = {}
    obj['vuln_name'] = vulnerability['plugin_name']
    obj['severity'] = severities[vulnerability['severity']]
    affected_hosts = []

    # Tüm Hostlarda Aynı Zafiyeti olanları [Affected Hosts] tespit etmek için:
    for host_response in hosts_response_list:
      json_response = json.loads(host_response.text)

      host_vulnerabilities = json_response['vulnerabilities']
      for vuln in host_vulnerabilities:
        if vuln['plugin_name'] == obj['vuln_name']:
          affected_hosts.append(json_response['info']['host-ip'])
      
      obj['affected_hosts'] = affected_hosts
    outputs.append(obj)
  return outputs

# Verileri .JSON Dosyasına yazdırmak için:
def main():
  response = get("scans/{}".format(scan_id))
  json_data = json.loads(response.text)

  hosts = json_data['hosts']
  extended_output, hosts_response_list = set_extended_output(hosts,scan_id)
  output = set_output(json_data,hosts_response_list)

  with open('Nessus_Export_Vulnerabilities.json', 'w') as f:
    json.dump(output, f, indent=4, sort_keys=True)

  with open('Nessus_Export_HostList.json', 'w') as f:
    json.dump(extended_output, f, indent=4, sort_keys=True)
 
 # AccessKey, SecretKey, URL ve ScanID değerlerini config.txt içerisinden çekmek için: 
def read_config():
  config = configparser.ConfigParser()
  config.read("config.txt")

  access_key = config.get("config", "access")
  secret_key = config.get("config", "secret")
  base_url = config.get("config", "url")
  scan_id = config.get("config", "scan_id")
  print("access ",access_key)
  print("secret ",secret_key)
  print("base url ",base_url)
  print("scan_id ",scan_id)
  return access_key, secret_key, base_url, scan_id

access_key, secret_key, base_url, scan_id = read_config()

main()
