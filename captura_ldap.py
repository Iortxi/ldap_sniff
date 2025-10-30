#!/usr/bin/env python3

import subprocess, signal, argparse, os, time

seguir = True
contador = 0
proceso_captura = None
proceso_activo = False


def segnal(sig, frame):
    global proceso_captura, seguir, contador, proceso_activo

    print('Señal recibida: %d' % sig, flush=True)

    if proceso_captura and proceso_activo:
        proceso_captura.send_signal(signal.SIGINT)
        proceso_captura.wait()
        proceso_activo = False

    if sig == signal.SIGUSR1:
        contador += 1
    elif sig == signal.SIGUSR2:
        seguir = False


# Instalar manejadores de señales
signal.signal(signal.SIGUSR1, segnal)   # ID = 10 -> Guardar captura y seguir
signal.signal(signal.SIGUSR2, segnal)   # ID = 12 -> Guardar captura y acabar


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interfaz', required=True, help='Interfaz de red en la que escuchar', type=str)
    parser.add_argument('-p', '--puerto', required=True, help='Puerto en el que escuchar', type=int)
    parser.add_argument('-n', '--nombre', required=True, help='Nombre base para los ficheros de captura', type=str)

    args = parser.parse_args()

    nombre = args.nombre
    interfaz = args.interfaz
    puerto = args.puerto

    print('PID del proceso -> %d' % (os.getpid()), flush=True)

    while seguir:
        comando = ["tcpdump", "-n", "-v", "-i", interfaz, "port", str(puerto), "-w", "%s_%d.pcap" % (nombre, contador)]
        #comando = ["snoop", "-o", "%s_%d.pcap" % (nombre, contador), "-d", interfaz, "port", str(puerto)]

        proceso_captura = subprocess.Popen(comando, stderr=subprocess.DEVNULL)
        proceso_activo = True

        try:
            while proceso_activo and seguir:
                time.sleep(0.5)
        except KeyboardInterrupt:
            break

    print('Fin', flush=True)
