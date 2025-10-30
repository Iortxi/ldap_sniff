#!/usr/bin/env python3

import argparse, sys, os, shutil, pyshark
from ssh import *
from enum import Enum
from scapy.utils import RawPcapReader, PcapWriter

# Traffic listeners supported (base commands)
listeners = {
    'snoop': "snoop -o /tmp/CONTADOR_NOMBRE.pcap -d INTERFAZ port PUERTO",
    'tcpdump': "tcpdump -n -v -i INTERFAZ port PUERTO -w /tmp/CONTADOR_NOMBRE.pcap",
}



""" Finaliza la ejecucion del programa con un mensaje de error y un codigo de estado """
def soltar_error(mensaje, codigo):
    print(f'\n[!] {mensaje}\n')
    sys.exit(codigo)



""" Genera el string con el comando de captura de trafico a ejecutar remotamente """
def actualizar_comando(escuchador, args, contador):
    return listeners[escuchador].replace('INTERFAZ', args.interface).replace('PUERTO', str(args.port)).replace('CONTADOR_NOMBRE', f"{contador}_{args.filename}")



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



""" Une dos capturas de trafico. Sobreescribe el nombre de la primera y borra la segunda """
# def unir_dos_capturas(captura1, captura2):
#     nombre_temporal = f"{captura1.split('.pcap')[0]}_temp.pcap"
#     writer = PcapWriter(nombre_temporal, sync=True)

#     for fname in [captura1, captura2]: # ¿Filtrar LDAP, bindRequests...?
#         for pkt_data, pkt_metadata in RawPcapReader(fname):
#             writer.write(pkt_data)

#     writer.close()

#     shutil.move(nombre_temporal, captura1)
#     os.remove(captura2)

def unir_dos_capturas(captura1, captura2):
    nombre_temporal = f"{captura1.split('.pcap')[0]}_temp.pcap"

    # Abrimos ambas capturas con filtro de display (LDAP bindRequest)
    capturas = [
        pyshark.FileCapture(captura1, display_filter="ldap.message.id and ldap and ldap.message.type == 0"),
        pyshark.FileCapture(captura2, display_filter="ldap.message.id and ldap and ldap.message.type == 0")
    ]

    # Creamos el writer
    with pyshark.FileCapture(output_file=nombre_temporal, use_json=True) as writer:
        for cap in capturas:
            for pkt in cap:
                writer.eventloop.packet_arrived(pkt)

    # Cerramos y reemplazamos archivos
    shutil.move(nombre_temporal, captura1)
    os.remove(captura2)




if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    # Flags de captura de trafico
    parser.add_argument('-i', '--interface', required=True, help='Network interface to listen', type=str)
    parser.add_argument('-p', '--port', required=True, help='Port to listen', type=int)
    parser.add_argument('-n', '--filename', required=True, help='Base name for capture files', type=str)

    # Flags de SSH
    parser.add_argument('-s', '--server', required=True, help='Remote SSH server', type=str)
    parser.add_argument('-u', '--user', required=True, help='Remote SSH user (able to capture LDAP traffic)', type=str)
    parser.add_argument('-pw', '--password', required=False, help='Remote SSH password', type=str)
    parser.add_argument('-pk', '--pkfile', required=False, help='Private key file', type=str)
    parser.add_argument('-pkp', '--pkfilepw', required=False, help='Private key passphrase if needed', type=str)
    parser.add_argument('-sshp', '--ssh_port', required=False, default=22, help='SSH port to connect (default 22)', type=int)

    args = parser.parse_args()

    ssh, scp = conectarse_a_host(args)

    escuchador = comando_escuchador(ssh)

    comando = actualizar_comando(escuchador, args, 0)

    primero = True

    nombre_captura_final = f'{args.filename}.pcap'

    contador = 0
    pid_remoto = iniciar_captura(ssh, comando)
    while True:
        try:
            opcion = recoger_opcion(primero)

            parar_captura(ssh, pid_remoto)

            recoger_y_borrar_captura(ssh, scp, args, contador)

            # Fusionar la captura recogida con las que ya habia
            if primero:
                primero = False
                shutil.move(f"0_{args.filename}.pcap", nombre_captura_final)
            else:
                unir_dos_capturas(nombre_captura_final, f'{contador}_{args.filename}.pcap')


            if opcion == 0: # Detener escuchador y seguir
                contador += 1
                comando = actualizar_comando(escuchador, args, contador)
                pid_remoto = iniciar_captura(ssh, comando)

            elif opcion == 1: # Detener escuchador y parar
                break

        except:
            print()
            continue

    scp.close()
    ssh.close()
