
import paramiko, os, time
from utils import soltar_error


class SSH:
    """ Clase con los metodos relacionados con las conexiones SSH de Paramiko """

    @staticmethod
    def conectarse_a_host(args):
        """ Establece la conexion SSH y devuelve sus sockets """

        # No se ha especificado ningun metodo de autenticacion
        if not args.pkfile and not args.password:
            soltar_error('Password or private key file required (authentication)', 1)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Si se especifica una clave privada, paramiko la busca y salta excepcion si no existe, aunque se haya introducido una contrasegna correcta
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


    @staticmethod
    def verificar_interfaz_red_remota(ssh: paramiko.SSHClient, args):
        """ Termina la ejecucion si la interfaz de red especificada por el usuario no existe en el servidor remoto """

        # Comando a ejecutar remotamente ('ifconfig -a' funciona en todos los SO basados en UNIX)
        comando = f'ifconfig -a | grep "{args.interface}: flags="'

        if not SSH.comando_ok(ssh, comando):
            soltar_error('Remote network interface does not exist', 5)


    @staticmethod
    def recoger_y_borrar_captura(ssh: paramiko.SSHClient, scp: paramiko.SFTPClient, args):
        """ Transfiere la captura remota y la borra en el servidor remoto """

        nombre_temporal = f'{args.filename}_temp'

        # Recoger captura guardada remotamente
        scp.get(f'/tmp/{nombre_temporal}', f'./{nombre_temporal}')
        
        # Borrar captura remota
        SSH.comando_ok(ssh, f'rm -f /tmp/{args.filename}')
        # del /f /q FICHERO -> Equivalente en Windows a rm -f FICHERO


    @staticmethod
    def comando_ok(ssh: paramiko.SSHClient, comando: str):
        """ Ejecuta remotamente un comando y devuelve True si ha sido exitoso (codigo de salida == 0) """

        # Ejecuta un comando pero no espera a que acabe
        _, stdout, _ = ssh.exec_command(comando)
        
        # Espera a que el comando termine y saca su codigo de salida
        codigo_salida = stdout.channel.recv_exit_status()

        return codigo_salida == 0


    @staticmethod
    def comando_remoto(ssh: paramiko.SSHClient, args, listeners: dict):
        """ Devuelve el comando a ejeutar en el servidor remoto para escuchar trafico """

        # Se itera sobre los programas de escucha disponibles. Se usa el primero que exista en la maquina remota
        for escuchador in listeners.keys():
            if SSH.comando_ok(ssh, f'which {escuchador}'):
                plantilla = listeners[escuchador]

                # Si el usuario ha especificado un puerto, se sustituye en el comando plantilla
                if args.port:
                    plantilla = plantilla.replace('PUERTO', str(args.port))
                
                # Si no, se elimina (en las plantillas, el puerto se pone lo ultimo y el nombre del fichero captura lo penultimo)
                else:
                    plantilla = plantilla.split('NOMBRE')[0] + 'NOMBRE'

                # Se reemplazan el resto de argumentos
                return listeners[escuchador].replace('INTERFAZ', args.interface).replace('NOMBRE', f'{args.filename}_temp')

        # Ningun programa de escucha de los disponibles existe en la maquina remota
        soltar_error('Any of the listeners supported are available on remote host', 5)


    @staticmethod
    def iniciar_captura(ssh: paramiko.SSHClient, comando_remoto: str):
        """ Inicia un proceso de captura remoto con el programa de captura disponible y devuelve su PID """

        # Comando que se va a dejar ejecutandose remotamente (nohup)
        comando = f'nohup {comando_remoto} > /dev/null 2>&1 & echo $!'

        # Se lanza el comando y se obtiene su PID
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


    @staticmethod
    def parar_captura(ssh: paramiko.SSHClient, pid: int, timeout: int = 3):
        """ Detiene el proceso de captura de trafico remoto """

        # Se intenta finalizar el proceso con la segnal SIGTERM
        ssh.exec_command(f'kill -TERM {pid} || true')
        time.sleep(timeout)

        # Verificamos si sigue vivo
        _, stdout, _ = ssh.exec_command(f'ps -p {pid} -o pid=')
        alive = stdout.read().decode().strip()

        # if alive:
        #     soltar_error('RAROOOOOO', 9)
        #     # Si sigue vivo, se fuerza con SIGKILL
        #     client.exec_command(f'kill -KILL {pid} || true')
