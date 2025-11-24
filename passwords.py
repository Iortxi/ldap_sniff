#!/usr/bin/env python3

import argparse, os
import utils


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LDAP passwords filter from a traffic capture file')
    parser.add_argument('-f', '--file', required=True, help='Traffic capture file (if not pcap, IT OVERWRITES IT)', type=str)
    parser.add_argument('-o', '--output', required=False, help='Output file for info (stdout default)', type=str)
    parser.add_argument('-n', required=False, help='Disable reverse DNS resolution', action='store_false')
    args = parser.parse_args()

    # La captura de trafico no existe
    if not os.path.isfile(args.file):
        utils.soltar_error('Traffic capture file does not exist', 1)

    # Convertir la captura de trafico si no esta en formato pcap
    utils.convertir_si_necesario(args.file)

    # Escribir la informacion de los LDAP bindRequests en un fichero o por pantalla
    w = None
    if args.output:
        w = open(args.output, 'w', buffering=1)

    utils.filtrar_paquetes(args.file, {}, args.n, True, w)

    if w is not None:
        w.close()
