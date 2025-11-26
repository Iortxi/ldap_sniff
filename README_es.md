
# LDAP_SNIFF

# NO ACABADO

**Idioma**
- Español 🇪🇸
- [English 🇬🇧](./README.md)


# Descripción general
Conjunto de scripts en Python para capturar información de *usuarios* y *contraseñas* en un servidor LDAP (**NO LDAPS**). Remota y localmente.


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
```bash
pip install -r requirements.txt
```


# Scripts
Aquí los scripts:
- [remote_capture.py](#remote_capturepy)
- [local_capture.py](#local_capturepy)
- [passwords.py](#passwordspy)

## remote_capture.py

Funciona así:
1. Establece una conexión SSH con un servidor remoto (contraseña o clave privada). **Debe ser con un usuario que pueda capturar tráfico**.
2. Se buscará un binario de captura de tráfico instalado en el servidor remoto. Soportados `snoop`, `tcpdump`, `tshark`, `dumpcap`. En [paquetes.py](#paquetespy) están las plantillas de ejecución para esos binarios, añade más si lo necesitas [PERO SIGUIENDO UNAS REGLAS](#paquetespy).
3. Se iniciará la captura de tráfico en la interfaz que hayas indicado y se guardará en el archivo `/tmp/NOMBRE_temp` del servidor remoto.
4. El programa esperará a que elijas una opción:

    0. Detener la captura, traer el archivo-captura a local, borrarlo en el servidor remoto, filtrar su tráfico LDAP con contraseñas (*bindRequests*) e iniciar **otra** captura en el servidor remoto (sigue ejecutando). Se dejará solo los paquetes LDAP con contraseñas en las capturas que se vayan transfiriendo del servidor remoto, y se irán mezclando en **un solo fichero de captura** (puedes elegir esta opción tantas veces como quieras).
    
    1. Lo mismo pero no inicia otra captura remota y detiene la ejecución.

Se usa SSH y SFTP con **paramiko** para **toda** la comunicación con el servidor remoto.


## local_capture.py
Básicamente lo mismo que [remote_capture.py](#remote_capturepy) pero en local.


## passwords.py
El más simple. Solo filtra las contraseñas LDAP de un archivo de captura y las imprime (stdout). El archivo-captura puede contener tráfico *no-LDAP*.

⚠️: **FUNCIONA CON CAPTURAS EN FORMATO PCAP, SI EL ARCHIVO NO ES PCAP, LO SOBRESCRIBE A PCAP**

# Ejemplos
Aquí algunos ejemplos de ejecución de la información capturada y los scripts.

### Información capturada parseada

De cada paquete LDAP con contraseña (bindRequest) se guarda información en este formato:
``` txt
IP_ORIGEN:IP_DESTINO:LDAP_DN:CONTRASEÑA
```

Ejemplo:
``` txt
156.131.157.114:121.214.161.142:cn=proxyagent,ou=profile,o=corp:PASs2
131.251.147.188:121.214.161.142:uid=peter,ou=People,o=corp:pass2
```

### remote_capture.py
``` bash
# Puerto 22 por defecto en el flag -sshp
# -n para deshabilitar resolución DNS inversa de IPs
# -v para verbose, ver la información capturada por pantalla durante la ejecución
# -o para guardar la información capturada en un fichero de texto. De todos modos se guarda en el fichero de captura final, y luego se puede parsear con passwords.py
./remote_capture.py -i eth0 -f capture_ldap.pcap -p 389 -s ssh-server.com -u peter -pw password -pk keys/id_rsa -pkp "key passphrase" [-sshp] 26 -n -v -o output.txt
```

### local_capture.py
``` bash
./local_capture.py -i eth0 -f capture_ldap.pcap -n -v -o output.txt
```

### passwords.py
``` bash
./passwords.py -f capture_ldap.pcap -n
```


# Módulos
Los scripts ejecutables también requieren algunos módulos:
- [ssh.py](#sshpy)
- [local.py](#localpy)
- [paquetes.py](#paquetespy)
- [rev_dns.py](#rev_dnspy)
- [utils.py](#utilspy)

## ssh.py
Módulo que contiene todo lo relacionado con SSH. Usa [Paramiko](https://www.paramiko.org/) para gestionar conexiones SSH y SFTP. Definitivamente la mejor librería de python para ello.

## local.py
La versión *local* de [ssh.py](#sshpy). Básicamente lo mismo pero sin SSH. Mucho más simple.

## paquetes.py
**Contiene las plantillas de los comandos de captura de tráfico**.
⚠️: **Si quieres añadir más, sigue esta sintaxis**:
- INTERFAZ es la interfaz de red.
- PUERTO es para filtrar trafico para solo un puerto. **AÑADE ESTE FILTRO EL ÚLTIMO EN EL COMANDO**.
- NOMBRE es el nombre del fichero-captura en el que estará todo el tráfico LDAP mezclado. **AÑADE ESTE EL PENÚLTIMO**.
Se puede ver cómo se utiliza esto en el método `comando_remoto()` de [ssh.py](#sshpy) y en el método `comando_escuchador()` de [local.py](#localpy).

Hace el tratamiento de paquetes para filtrar y escribir los paquetes LDAP que contienen contraseñas.

## rev_dns.py
Usa muchos servidores DNS públicos y una **cola circular** para balancear las peticiones DNS. Tiene solo una función que resuelve inversamente una IP y guarda esa relación (IP:nombre) para minimizar peticiones. Si no puede resolver una IP, devuelve la misma IP.

## utils.py
Módulo auxiliar con funciones varias.


# Gitignore
Mantiene solo archivos `.py`, `README` y `requirements.txt`.
