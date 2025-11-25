
import subprocess, os, signal, psutil
from utils import soltar_error


class Local:
    """ Clase con los metodos relacionados con el tratamiento de archivos y procesos de ejecucion """

    @staticmethod
    def verificar_interfaz_red(args):
        """ Finaliza la ejecucion si la interfaz de red que ha introducido el usuario no existe """

        # Diccionario con los nombres de las interfaces de red y su informacion
        interfaces = psutil.net_if_addrs()

        # Si la interfaz de red introducida no existe, la ejecucion termina
        if not args.interface in interfaces:
            soltar_error(f'Network interface {args.interface} does not exist', 1)


    @staticmethod
    def comando_ok(comando: str):
        """ Ejecuta un comando y devuelve True si se ha ejecutado correctamente """

        p = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return p.returncode == 0


    @staticmethod
    def comando_escuchador(args, listeners: dict):
        """ Devuelve el comando a ejeutar localmente para escuchar trafico """

        # Se itera sobre los programas de escucha disponibles. Se usa el primero que exista en la maquina remota
        for escuchador in listeners.keys():
            if Local.comando_ok(f'which {escuchador}'):
                return listeners[escuchador].replace('INTERFAZ', args.interface).replace('NOMBRE', f'{args.filename}_temp')

        # Ningun programa de escucha de los disponibles existe en la maquina remota
        soltar_error('Any of the listeners supported are available on remote host', 5)


    @staticmethod
    def iniciar_captura(comando: str):
        """ Inicia un proceso en segundo plano con un programa de captura que este instalado y devuelve su PID """

        proceso_captura = subprocess.Popen(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return proceso_captura.pid


    @staticmethod
    def parar_captura(pid: int):
        """ Detiene el proceso de captura de trafico """

        # Se envia la segnal al proceso de captura para que se detenga
        os.kill(pid, signal.SIGTERM)

        try:
            # Se comprueba si el proceso sigue vivo
            os.kill(pid, 0)
        
        # Si salta alguna excepcion, el proceso se ha detenido correctamente
        except:
            pass

        # Si no salta ninguna excepcion es que el proceso sigue vivo, se fuerza a que acabe con SIGKILL
        else:
            os.kill(pid, signal.SIGKILL)
