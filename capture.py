#!/usr/bin/env python3

import argparse, os, shutil
from ssh import *
from scapy.all import PcapWriter
from utils import *


# Traffic listeners supported (base commands)
listeners = {
    'snoop': 'snoop -o /tmp/NOMBRE -d INTERFAZ port PUERTO',
    'tcpdump': 'tcpdump -n -v -i INTERFAZ port PUERTO -w /tmp/NOMBRE',
}



def recoger_opcion(mostrar_menu: bool):
    """ Queda a la espera de que el usuario ejecute una opcion. Opcionalmente muestra menu de opciones """

    # Menu de opciones
    if mostrar_menu:
        print('\n------------------ OPTIONS ------------------')
        print('[0] Collect remote capture and keep capturing')
        print('[1] Collect remote capture and stop capturing\n')

    # Espera
    input_ = input('\n[?] Select an option (0 or 1): ')

    # Bucle infinito hasta obtener un resultado valido
    while True:
        try:
            opcion = int(input_)
            if opcion != 0 and opcion != 1:
                raise ValueError
            break
        except ValueError:
            input_ = input('\n[!] Give a valid option (0 or 1): ')
    
    return opcion



def comando_remoto(ssh: paramiko.SSHClient, args):
    """ Devuelve el comando a ejeutar en el servidor remoto para escuchar trafico """

    # Diccionario con los programas de escucha disponibles y las plantillas de sus comandos
    global listeners

    # Se itera sobre los programas de escucha disponibles. Se usa el primero que exista en la maquina remota
    for escuchador in listeners.keys():
        if comando_ok(ssh, f'which {escuchador}'):
            return listeners[escuchador].replace('INTERFAZ', args.interface).replace('PUERTO', str(args.port)).replace('NOMBRE', args.filename)

    # Ningun programa de escucha de los disponibles existe en la maquina remota
    soltar_error('Any of the listeners supported are available on remote host', 5)



def unir_dos_capturas(captura1: str, captura2: str, writer_output, dict_dns: dict, resolver_dns: bool, verbose: bool):
    """ Agnade los bindRequests de la segunda captura a la primera y borra la segunda """

    # Escritor en modo append para no sobreescribir los paquetes ya existentes
    writer_captura = PcapWriter(captura1, append=True, sync=True)

    # Se filtran los paquetes LDAP BindRequest de la nueva captura recogida y se fusionan con los que ya se han filtrado
    filtrar_paquetes(captura2, dict_dns, resolver_dns, verbose, writer_output, writer_captura)

    # Eliminar la segunda captura (sus paquetes ya se han fusionado con todos los anteriores)
    os.remove(captura2)

    # Se cierra el escritor
    writer_captura.close()



def filtrar_ldap_primera_captura(captura: str, writer_output, dict_dns: dict, resolver_dns: bool, verbose: bool):
    """ Filtra los bindRequests de una captura en formato pcap y la sobreescribe """

    # Nombre temporal del fichero de captura con solo los paquetes LDAP
    nombre_temporal = f'{captura}_temp'

    # Si ya existe localmente una captura de trafico con ese nombre, se sobreescribe
    if os.path.isfile(nombre_temporal):
        os.remove(nombre_temporal)

    # Escritor del fichero de captura
    writer_captura = PcapWriter(nombre_temporal, sync=True)

    # Se filtran los paquetes LDAP BindRequest de la primera captura recogida y se escriben en la captura temporal
    filtrar_paquetes(captura, dict_dns, resolver_dns, verbose, writer_output, writer_captura)

    # Se reemplaza el nombre temporal por el especificado por el usuario
    shutil.move(nombre_temporal, captura)

    # Se cierra el escritor
    writer_captura.close()




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Remote LDAP sniffer with SSH')

    # Flags de captura de trafico
    parser.add_argument('-i', '--interface', required=True, help='Remote network interface to listen', type=str)
    parser.add_argument('-p', '--port', required=True, help='Remote LDAP port to listen (default 389)', type=int, default=389)
    parser.add_argument('-f', '--filename', required=True, help='File name for the mixed traffic capture file', type=str)

    # Flags de SSH
    parser.add_argument('-s', '--server', required=True, help='Remote SSH server', type=str)
    parser.add_argument('-u', '--user', required=True, help='Remote SSH user (able to capture traffic in the LDAP port)', type=str)
    parser.add_argument('-pw', '--password', required=False, help='Remote SSH user password', type=str)
    parser.add_argument('-pk', '--pkfile', required=False, help='Private key file', type=str)
    parser.add_argument('-pkp', '--pkfilepw', required=False, help='Private key passphrase if needed', type=str)
    parser.add_argument('-sshp', '--ssh_port', required=False, default=22, help='SSH port to connect (default 22)', type=int)

    # Flag de output de informacion (IPs origen y destino, DN y contrasegna) en fichero de texto plano
    parser.add_argument('-o', '--output', required=False, help='Output file for info', type=str)

    # Flag de resolucion inversa DNS
    parser.add_argument('-n', required=False, help='Disable reverse DNS resolution', action='store_false')

    # Flag de verbose
    parser.add_argument('-v', required=False, help='Verbose. See the info captured during execution', action='store_true')

    # Argumentos parseados
    args = parser.parse_args()

    # Variables auxiliares
    primero = True
    nombre_temporal = f'{args.filename}_temp'
    dict_dns = {}
    writer_output = None

    # Se ha especificado un fichero de salida de informacion
    if args.output:
        writer_output = open(args.output, 'w', encoding='utf-8', buffering=1)

    # Sockets de la conexion remota SSH para ejecutar comandos y transferir archivos
    ssh, scp = conectarse_a_host(args)

    # Comando de captura a ejecutar remotamente
    comando = comando_remoto(ssh, args)

    # Se inicia la primera captura
    pid_remoto = iniciar_captura(ssh, comando)

    # Bucle infinito de ejecucion
    while True:
        try:
            # Espera a que el usuario seleccione una opcion
            opcion = recoger_opcion(primero)

            # En cuanto el usuario elige una opcion, se detiene la captura de trafico remota
            parar_captura(ssh, pid_remoto)

            # Se toma la captura de trafico remota y se borra en el servidor remoto
            recoger_y_borrar_captura(ssh, scp, args)

            # Convertir la captura recogida a formato pcap si es necesario
            convertir_si_necesario(nombre_temporal)

            # Es la primera vez que se detiene una captura
            if primero:
                # Se modifica el nombre de la primera captura recogida
                shutil.move(nombre_temporal, args.filename)

                # Filtrar trafico LDAP de la primera captura y sobreescribirla
                filtrar_ldap_primera_captura(args.filename, writer_output, dict_dns, args.n, args.v)

                primero = False

            # No es la primera captura que se detiene
            else:
                # Se filtra el trafico LDAP de la captura remota recogida y se une a las ya existentes en una sola
                unir_dos_capturas(args.filename, nombre_temporal, writer_output, dict_dns, args.n, args.v)


            # Detener captura e iniciar otra
            if opcion == 0:
                pid_remoto = iniciar_captura(ssh, comando)

            # Detener captura y salir del bucle
            elif opcion == 1:
                break

        # Detener ejecucion si ocurre cualquier excepcion no esperada
        except:
            scp.close()
            ssh.close()
            soltar_error('[!] Unexpected exception', 4)

    scp.close()
    ssh.close()
