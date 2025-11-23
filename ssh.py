
import paramiko, os, time
from utils import soltar_error


""" Establece la conexion SSH y devuelve sus sockets """
def conectarse_a_host(args):
    # No se ha especificado ningun metodo de autenticacion
    if not args.pkfile and not args.password:
        soltar_error('Password or private key file required (authentication)', 1)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Si se especifica una clave privada, paramiko siempre la busca y salta excepcion si no existe, aunque la contrasegna sea correcta
    if args.pkfile and not os.path.isfile(args.pkfile):
        args.pkfile = None

    # Autenticacion por contrasegna o clave privada
    try:
        ssh.connect(hostname=args.server, username=args.user, port=args.ssh_port, password=args.password, key_filename=args.pkfile, passphrase=args.pkfilepw)
    except paramiko.AuthenticationException:
        soltar_error('SSH authentication failed', 2)
    except:
        soltar_error('SSH session could not be established for no authentication reason', 3)

    return ssh, ssh.open_sftp()



""" Recoge la captura remota guardada y la borra en el servidor remoto """
def recoger_y_borrar_captura(ssh, scp, args):
    # Recoger captura guardada remotamente
    scp.get(f'/tmp/{args.filename}', f'{args.filename}_temp')
    
    # Borrar captura remota
    comando_ok(ssh, f'rm -f /tmp/{args.filename}')
    # del /f /q FICHERO -> Equivalente en Windows a rm -f FICHERO



""" Ejecuta remotamente un comando y devuelve True si se ha ejecutado correctamente """
def comando_ok(ssh, comando):
    # Ejecuta un comando pero no espera a que acabe
    _, stdout, _ = ssh.exec_command(comando)
    
    # Espera a que el comando termine y saca su codigo de salida
    codigo_salida = stdout.channel.recv_exit_status()

    return codigo_salida == 0



""" Inicia un proceso de captura remoto con el programa de captura disponible y devuelve su PID """
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



""" Detiene el proceso de captura de trafico remoto """
def parar_captura(ssh, pid, timeout=3):
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
