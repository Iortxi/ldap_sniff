
from capture import soltar_error
import paramiko, os, time


""" Genera el objeto clave privada a partir de un fichero con una clave privada """
def clave_privada(args):

    if not os.path.isfile(args.pkfile):
        soltar_error('Private key file does not exist', 2)

    tipos_claves = [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]

    for tipo in tipos_claves:
        try:
            key = tipo.from_private_key_file(args.pkfile, args.pkfilepw)
            return key
        except:
            continue

    soltar_error('Private key type not identified (accepted RSA, ED25519, ECDSA, DSA) or passphrase incorrect', 3)



""" Establece la conexion SSH y devuelve sus sockets """
def conectarse_a_host(args):
    if not args.pkfile and not args.password:
        soltar_error('Password or private key file required (authentication)', 1)


    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if args.password:
        try:
            ssh.connect(hostname=args.server, username=args.user, password=args.password, port=args.ssh_port)
        except:
            soltar_error('SSH session could not be established', 4)
    else:
        pkey = clave_privada(args)
        try:
            ssh.connect(hostname=args.server, username=args.user, pkey=pkey, port=args.ssh_port)
        except:
            soltar_error('SSH session could not be established', 4)

    return ssh, ssh.open_sftp()



""" Recoge la captura remota guardada y la borra en el servidor remoto """
def recoger_y_borrar_captura(ssh, scp, args, contador):
    # Nombre del fichero
    fichero = f'{contador}_{args.filename}.pcap'

    # Recoger captura guardada remotamente
    scp.get(f'/tmp/{fichero}', fichero)
    
    # Borrar captura remota
    comando_ok(ssh, f'rm -f /tmp/{fichero}')



""" Ejecuta remotamente un comando y devuelve si ha sido exitoso o no """
def comando_ok(ssh, comando):
    # Ejecuta un comando pero no espera a que acabe
    _, stdout, _ = ssh.exec_command(comando)
    
    # Espera a que el comando termine y saca su codigo de estado
    codigo_estado = stdout.channel.recv_exit_status()

    return codigo_estado == 0



""" Inicia remotamente un proceso de captura con el programa de captura disponible """
def iniciar_captura(ssh, comando_remoto):
    comando = f"nohup {comando_remoto} > /dev/null 2>&1 & echo $!"

    _, stdout, _ = ssh.exec_command(comando)
    pid = stdout.read().decode().strip()

    # if not pid.isdigit():
    #         # Buscar el proceso por nombre del comando
    #         stdin2, stdout2, stderr2 = client.exec_command(f"pgrep -f '{comando_remoto.split()[0]}' || true")
    #         pids = stdout2.read().decode().strip().split()
    #         pid = pids[0] if pids else ""
    #     if not pid:
    #         "No se pudo obtener el PID remoto"

    return int(pid)



""" Detiene remotamente el proceso de captura de trafico """
def parar_captura(ssh, pid, timeout=2):
    # Intentamos terminar el proceso con SIGTERM
    ssh.exec_command(f"kill -TERM {pid} || true")
    time.sleep(timeout)

    # Verificamos si sigue vivo
    _, stdout, _ = ssh.exec_command(f"ps -p {pid} -o pid=")
    alive = stdout.read().decode().strip()

    # if alive:
    #     soltar_error('RAROOOOOO', 9)
    #     # Si sigue vivo, lo forzamos con SIGKILL
    #     client.exec_command(f"kill -KILL {pid} || true")
