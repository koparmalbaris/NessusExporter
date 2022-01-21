# NessusExporter

Nessus zafiyet taramasından:
Taranan sunuculara ait; hostname, IP adresi ve işletim sistemi bilgilerini, Zafiyetler üzerinden; zafiyetin adı, seviyesi ve ilgili zafiyetten etkilenmekte olan sunucu bilgilerini .JSON formatında export etmeyi amaçlayan basit script.


Scriptin çalıştırılmasından sonra:

Nessus_Export_HostList.json dosyası için Örnek Data Seti

{"hostname":"metasploitable", "ip_address":"192.168.1.5", "OS":"Windows Server 2012 R2"}

Nessus_Export_Vulnerabilities.json dosyası için Örnek Data Seti

{"vuln_name":"PrintNightmare", "severity":"Critical", "affected_hosts":["xxx","xxx"], …}


# Usage

İlgili python scripti çalıştırılmadan önce, config.txt dosyası içerisine:

  - access = Nessus'dan alınan AccessKey girilmeli
  - secret = Nessus'dan alınan SecretKey girilmeli
  - url = Nessus'un çalışmakta olduğu URL adresi girilmeli
  - scan_id = Çıktısı alınmak istenen zafiyet taramasının Scan ID değeri girilmeli

Scriptin çalıştırılabilmesi için:

  - python3 NessusExporter.py



Config.txt Sample

![1](https://user-images.githubusercontent.com/45037356/150573599-3201016b-ac7b-4d28-a79a-16aa1ed67730.png)

