#!/usr/bin/env python3

import argparse, shutil
from paquetes import Trafico
from local import Local
from utils import *


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Local LDAP password sniffer')

    # Flags de captura de trafico
    parser.add_argument('-i', '--interface', required=True, help='Local network interface to listen', type=str)
    parser.add_argument('-f', '--filename', required=True, help='File name for the mixed traffic capture file', type=str)

    # Flag de output de informacion (IPs origen y destino, DN y contrasegna) en fichero de texto plano
    parser.add_argument('-o', '--output', required=False, help='Output file for info', type=str)

    # Flag de resolucion inversa DNS
    parser.add_argument('-n', required=False, help='Disable reverse DNS resolution', action='store_false')

    # Flag de verbose
    parser.add_argument('-v', required=False, help='Verbose. See the info captured during execution', action='store_true')

    # Argumentos parseados
    args = parser.parse_args()

    # Se verifica si la interfaz de red introducida por el usuario existe
    Local.verificar_interfaz_red(args)

    # Variables auxiliares
    primero = True
    nombre_temporal = f'{args.filename}_temp'
    dict_dns = {}
    writer_output = None

    # Se ha especificado un fichero de salida de informacion
    if args.output:
        writer_output = open(args.output, 'w', encoding='utf-8', buffering=1)

    # Comando a ejecutar localmente para capturar trafico
    comando = Local.comando_escuchador(args, Trafico.listeners)

    # PID del primer proceso de captura
    pid = Local.iniciar_captura(comando)

    # Bucle principal de ejecucion
    while True:
        try:
            # Espera a que el usuario seleccione una opcion
            opcion = recoger_opcion(primero)

            # Cuando el usuario ha elegido una opcion, se detiene el proceso de captura
            Local.parar_captura(pid)

            # Mover la captura de /tmp al directorio local
            shutil.move(f'/tmp/{nombre_temporal}', '.')

            # Se convierte la captura a formato pcap si no lo esta
            Trafico.convertir_si_necesario(nombre_temporal)

            # Es la primera captura de trafico que se toma
            if primero:
                # Filtrar trafico LDAP de la primera captura y sobreescribirla
                Trafico.filtrar_ldap_primera_captura(args.filename, writer_output, dict_dns, args.n, args.v)

                primero = False

            # No es la primera captura de trafico que se toma
            else:
                # Se junta la nueva captura con las anteriores
                Trafico.unir_dos_capturas(args.filename, nombre_temporal, writer_output, dict_dns, args.n, args.v)


            # Detener la captura y seguir
            if opcion == 0:
                # PID del nuevo proceso de captura
                pid = Local.iniciar_captura(comando)

            # Detener la captura y terminar la ejecucion
            else:
                break

        except:
            Local.parar_captura(pid)
            soltar_error('Unexpected exception', 1)
