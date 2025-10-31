#!/usr/bin/env python3

import argparse, os, sys
from scapy.all import TCP, IP, RawPcapReader, Ether


def parsear_ldap_bind(payload):
    """
    Extrae el nombre y la contraseña (simple bind) de un paquete LDAP BindRequest
    """
    try:
        if payload[0] != 0x30:
            return None, None

        idx = payload.index(0x60)  # BindRequest start
        cursor = idx + 2  # Skip 0x60 and length byte

        # Skip version (usually 0x02 0x01 0x03 for version 3)
        if payload[cursor] == 0x02:
            cursor += 2  # tag + length
            cursor += 1  # skip version value

        # Extract name (LDAPDN, usually an Octet String - tag 0x04)
        nombre = ""
        if payload[cursor] == 0x04:
            name_len = payload[cursor + 1]
            name_bytes = payload[cursor + 2:cursor + 2 + name_len]
            nombre = name_bytes.decode(errors="ignore")
            cursor = cursor + 2 + name_len

        # Extract simple password (tag 0x80)
        password = ""
        if payload[cursor] == 0x80:
            pwd_len = payload[cursor + 1]
            pwd_bytes = payload[cursor + 2:cursor + 2 + pwd_len]
            password = pwd_bytes.decode(errors="ignore")

        return nombre, password

    except:
        return None, None



# Funcion que devuelva un booleano. True si un paquete (parametro) es un bindRequest, que utilice parsear_ldap_bind()
def paquete_ldap_bind_request(paquete):
    if IP in paquete and TCP in paquete and paquete[TCP].payload and paquete[TCP].dport == 389:
        raw = bytes(paquete[TCP].payload)
        if len(raw) > 0 and 0x60 in raw and raw[0] == 0x30:
            nombre, passwd = parsear_ldap_bind(raw)
            return nombre and passwd, nombre, passwd
    return False, None, None



def filtrar_paquetes(captura):
    for paquete, _ in RawPcapReader(captura):
        pkt = Ether(paquete)
        es_bind_request, nombre, passwd = paquete_ldap_bind_request(pkt)
        if es_bind_request:
            print(f'{pkt[IP].src}:{pkt[IP].dst}:{nombre}:{passwd}')




# De formato snoop a formato pcap:
#################################################################################
# BASH:
# editcap -F pcap ejemplo_ldap_pass.cap ejemplo_ldap_pass.pcap
#################################################################################
# PYTHON:
# from scapy.all import rdpcap, wrpcap

# # Lee el archivo .cap (por ejemplo, en formato pcapng)
# packets = rdpcap("captura.cap")

# # Escribe los paquetes en formato .pcap clásico
# wrpcap("captura.pcap", packets)
#################################################################################


# Verificar formato de una captura:
#################################################################################
# PYTHON:
# def detectar_formato_pcap(ruta):
#     with open(ruta, "rb") as f:
#         magic = f.read(4)

#     if magic == b'\xd4\xc3\xb2\xa1' or magic == b'\xa1\xb2\xc3\xd4':
#         return "pcap"
#     elif magic == b'\x0a\x0d\x0d\x0a':
#         return "pcapng"
#     else:
#         return "desconocido"



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='Traffic capture file (pcap)', type=str)
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print('[!] Traffic capture file does not exist')
        sys.exit(1)

    filtrar_paquetes(args.file)
