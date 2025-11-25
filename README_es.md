
# LDAP_SNIFF

# NO ACABADO

**Idioma**
- Español 🇪🇸
- [English 🇬🇧](./README.md)


# Descripción general
Conjunto de scripts en Python para olfateo (sniff) de *usuarios* y contraseñas LDAP (**NO LDAPS**).


# Índice
- [Requisitos](#requisitos)
- [Scripts](#scripts)
    - [remote_capture.py](#remote_capturepy)
    - [local_capture.py](#localpy)
    - [passwords.py](#passwordspy)
- [Ejemplos](#ejemplos)
    - [remote_capture.py](#remote_capturepy)
    - [local_capture.py](#localpy)
    - [passwords.py](#passwordspy)
    - [Información capturada parseada](#información-capturada-parseada)
- [Módulos](#módulos)
    - [ssh.py](#sshpy)
    - [local.py](#localpy)
    - [paquetes.py](#paquetespy)
    - [rev_dns.py](#rev_dnspy)
    - [utils.py](#utilspy)
- [Gitignore](#gitignore)


# Requisitos
**IMPORTANTE**: Instalar las dependencias de `requirements.txt`.


# Scripts
Aquí los scripts:
- [remote_capture.py](#remote_capturepy)
- [local_capture.py](#local_capturepy)
- [passwords.py](#passwordspy)

## remote_capture.py

Funciona así:
1. Establece una conexión SSH con un servidor remoto (contraseña o clave privada). **Debes iniciar sesión como un usuario que pueda capturar tráfico**.
2. Buscará un binario de captura de tráfico instalado en el servidor remoto. Soporta `snoop`, `tcpdump`. En [paquetes.py](#paquetespy) encontrarás las plantillas de ejecución para esos binarios; añade más si lo necesitas. 3. Iniciará la captura de tráfico en el archivo `/tmp/NAME_temp` del servidor remoto. 4. Esperará a que elijas una opción:

    0. Detener la captura, traer el archivo al sistema local, borrarlo del servidor remoto, filtrar el tráfico LDAP e iniciar **otra** captura en el servidor remoto (sigue ejecutando). También mezcla el tráfico LDAP recién capturado con otros archivos de captura (puedes elegir esta opción tantas veces como quieras).
    1. Lo mismo, pero detiene la ejecución. No iniciará otra captura remota.

Se usa SSH y SFTP con **paramiko** para **toda** la comunicación con el servidor remoto.


## local_capture.py
Básicamente lo mismo que [remote_capture.py](#remote_capturepy) pero local.


## passwords.py
El más simple. Solo filtra las contraseñas LDAP de un archivo de captura y las imprime (stdout). El archivo puede contener tráfico *no-LDAP*. Resolución DNS inversa opcional.

⚠️: **FUNCIONA CON FORMATO PCAP; SI EL ARCHIVO NO ES PCAP, LO SOBRESCRIBE A PCAP**

# Ejemplos
Aquí algunos ejemplos de ejecución de los scripts y la información capturada.

### remote_capture.py
``` bash
./remote_capture.py -i eth0 -f capture_ldap.pcap -s example.com -u peter -p password -pk id_rsa -pkp "key passphrase" [-sshp] 26 -n -v -o output.txt
```


### local_capture.py
``` bash
./local_capture.py -i eth0 -f capture_ldap.pcap -n -v -o output.txt
```


### passwords.py
``` bash
./passwords.py -f capture_ldap.pcap -n
```



### Información capturada parseada

Cada paquete LDAP con contraseña tiene este formato:
``` txt
IP_ORIGEN:IP_DESTINO:LDAP_DN:CONTRASEÑA
```

Ejemplo:
``` txt
156.131.157.114:121.214.161.142:cn=proxyagent,ou=profile,o=corp:PASs2
131.251.147.188:121.214.161.142:uid=peter,ou=People,o=corp:pass2
```

# Módulos
Los scripts ejecutables también requieren algunos módulos:
- [ssh.py](#sshpy)
- [local.py](#localpy)
- [paquetes.py](#paquetespy)
- [rev_dns.py](#rev_dnspy)
- [utils.py](#utilspy)


## ssh.py
Módulo que contiene todo el trabajo relacionado con SSH. Usa [Paramiko](https://www.paramiko.org/) para gestionar conexiones SSH y SFTP. Ejecuta comandos remotos para capturar tráfico y borrar evidencia en el servidor.


## local.py
La versión *local* de [ssh.py](#sshpy). Básicamente lo mismo pero sin SSH. Mucho más simple.


## paquetes.py
**Contiene las plantillas de los comandos de captura de tráfico**, añade más si lo necesitas. Hace el tratamiento de paquetes para filtrar y escribir los paquetes LDAP que contienen contraseñas. También realiza la resolución DNS inversa **opcional**.

## rev_dns.py

Usa muchos servidores DNS públicos y una **cola circular** para balancear las peticiones. Tiene solo una función que resuelve una IP a nombre DNS y guarda esa información para minimizar peticiones. Si no puede resolver, devuelve la IP.

## utils.py

Módulo auxiliar con funciones varias. No relacionado con SSH ni tratamiento de paquetes.

# Gitignore

Mantiene solo archivos `.py`, `README` y `requirements.txt`.
