#!/usr/bin/env python3

import argparse, os, shutil
from ssh import *
from scapy.all import PcapWriter
from passwords_ldap import *
from utils import *


# Traffic listeners supported (base commands)
listeners = {
    'snoop': 'snoop -o /tmp/NOMBRE -d INTERFAZ port PUERTO',
    'tcpdump': 'tcpdump -n -v -i INTERFAZ port PUERTO -w /tmp/NOMBRE',
}



""" Genera el string con el comando de captura de trafico a ejecutar remotamente """
def actualizar_comando(escuchador, args):
    return listeners[escuchador].replace('INTERFAZ', args.interface).replace('PUERTO', str(args.port)).replace('NOMBRE', args.filename)



""" Queda a la espera de que el usuario ejecute una opcion """
def recoger_opcion(mostrar_menu):
    # Menu de opciones
    if mostrar_menu:
        print('\n------------------ OPTIONS ------------------')
        print('[0] Collect remote capture and keep capturing')
        print('[1] Collect remote capture and stop capturing\n')

    input_ = input('\n[?] Select an option (0 or 1): ')

    while True:
        try:
            opcion = int(input_)
            if opcion != 0 and opcion != 1:
                raise ValueError
            break
        except ValueError:
            input_ = input('\n[!] Give a valid option (0 or 1): ')
    
    return opcion



""" Devuelve un objeto Listener con el programa de captura que este disponible en el servidor remoto """
def comando_escuchador(ssh):
    global listeners

    for escuchador in listeners.keys():
        if comando_ok(ssh, f'which {escuchador}'):
            return escuchador

    soltar_error('Any of the listeners supported are available on remote host', 5)



""" Agnade los bindRequests de la segunda captura a la primera y borra la segunda """
def unir_dos_capturas(captura1, captura2, output):
    writer = PcapWriter(captura1, append=True, sync=True)
    generica(captura2, output, writer, False)
    os.remove(captura2)



""" Filtra los bindRequests de una captura en formato pcap y la sobreescribe """
def filtrar_ldap_primera_captura(captura, output):
    nombre_temporal = f'{captura}_temp'
    writer = PcapWriter(nombre_temporal, sync=True)
    generica(captura, output, writer, True)
    shutil.move(nombre_temporal, captura)



"""  """
def generica(captura, output, writer, primero):
    w = None
    if output and primero:
        w = open(output, 'w', encoding='utf-8', buffering=1)
    elif output and not primero:
        w = open(output, 'a', encoding='utf-8', buffering=1)

    filtrar_paquetes(captura, w, writer)

    writer.close()
    if w is not None:
        w.close()




if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    # Flags de captura de trafico
    parser.add_argument('-i', '--interface', required=True, help='Remote network interface to listen', type=str)
    parser.add_argument('-p', '--port', required=True, help='Remote LDAP port to listen', type=int)
    parser.add_argument('-f', '--filename', required=True, help='File name for the mixed traffic capture', type=str)

    # Flags de SSH
    parser.add_argument('-s', '--server', required=True, help='Remote SSH server', type=str)
    parser.add_argument('-u', '--user', required=True, help='Remote SSH user (able to capture LDAP traffic)', type=str)
    parser.add_argument('-pw', '--password', required=False, help='Remote SSH password', type=str)
    parser.add_argument('-pk', '--pkfile', required=False, help='Private key file', type=str)
    parser.add_argument('-pkp', '--pkfilepw', required=False, help='Private key passphrase if needed', type=str)
    parser.add_argument('-sshp', '--ssh_port', required=False, default=22, help='SSH port to connect (default 22)', type=int)

    # Flag de output de contrasegnas
    parser.add_argument('-o', '--output', required=False, help='Output file for info (stdout default)', type=str)

    args = parser.parse_args()

    ssh, scp = conectarse_a_host(args)

    escuchador = comando_escuchador(ssh)

    comando = actualizar_comando(escuchador, args)

    primero = True
    nombre_temporal = f'{args.filename}_temp'

    pid_remoto = iniciar_captura(ssh, comando)
    while True:
        try:
            opcion = recoger_opcion(primero)

            parar_captura(ssh, pid_remoto)

            recoger_y_borrar_captura(ssh, scp, args)

            if primero:
                primero = False
                shutil.move(nombre_temporal, args.filename)
                convertir_si_necesario(args.filename)
                filtrar_ldap_primera_captura(args.filename, args.output)
            else:
                convertir_si_necesario(nombre_temporal)
                unir_dos_capturas(args.filename, nombre_temporal, args.output)


            if opcion == 0: # Detener escuchador y seguir
                pid_remoto = iniciar_captura(ssh, comando)

            elif opcion == 1: # Detener escuchador y parar
                break

        except:
            scp.close()
            ssh.close()
            soltar_error('[!] Unexpected exception', 5)

    scp.close()
    ssh.close()
