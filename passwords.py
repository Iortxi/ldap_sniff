#!/usr/bin/env python3

import argparse, os
from utils import *


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Filters LDAP passwords from a traffic capture file')
    parser.add_argument('-f', '--file', required=True, help='Traffic capture file (if not pcap, it OVERWRITES)', type=str)
    parser.add_argument('-o', '--output', required=False, help='Output file for info (stdout default)', type=str)
    args = parser.parse_args()

    # La captura de trafico no existe
    if not os.path.isfile(args.file):
        soltar_error('Traffic capture file does not exist', 1)

    # La captura de trafico no esta en formato pcap
    convertir_si_necesario(args.file)

    # Escribir la informacion de los LDAP bindRequests en un fichero o por pantalla
    w = None
    if args.output:
        w = open(args.output, 'w', buffering=1)

    filtrar_paquetes(args.file, w)

    if w is not None:
        w.close()
