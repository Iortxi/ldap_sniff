#!/usr/bin/env python3

import argparse, os, sys
from utils import *


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='Traffic capture file (only pcap)', type=str)
    parser.add_argument('-o', '--output', required=False, help='Output file for info (stdout default)', type=str)
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print('[!] Traffic capture file does not exist')
        sys.exit(1)

    convertir_si_necesario(args.file)

    w = None
    if args.output:
        w = open(args.output, 'w', buffering=1)

    filtrar_paquetes(args.file, w)

    if w is not None:
        w.close()
