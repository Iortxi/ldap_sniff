
import os, rev_dns
from scapy.all import IP, RawPcapReader, Ether, PcapWriter
from pyasn1.codec.ber import decoder
from pyasn1_ldap.rfc4511 import LDAPMessage
from io import TextIOWrapper


class Trafico:
    """ Clase con los metodos relacionados con el tratamiendo de paquetes. """

    # Traffic listeners supported (base commands)
    listeners = {
        'snoop': 'snoop -d INTERFAZ -o /tmp/NOMBRE port PUERTO',
        'tcpdump': 'tcpdump -n -i INTERFAZ -w /tmp/NOMBRE port PUERTO',
        'tshark': 'tshark -n -i INTERFAZ -w /tmp/NOMBRE -f "port PUERTO"',
        'dumpcap': 'dumpcap -n -i INTERFAZ -w /tmp/NOMBRE -f "port PUERTO"',
    }


    @staticmethod
    def es_bind_request(data: bytes) -> bool:
        """
        Analiza un paquete de red.

        Args:
            data: Paquete de red a analizar (formato bytes).

        Returns:
            bool: True si el paquete es un LDAP bindRequest, False en caso contrario.
        """

        try:
            # Se calcula el offset a partir del cual empieza la capa LDAP
            offset = data.find(b'\x30')

            # Bytes de la capa LDAP
            ldap = data[offset:]

            # Capa LDAP parseada
            msg, _ = decoder.decode(ldap, asn1Spec=LDAPMessage())

            # Devuelve True si el tipo de paquete LDAP es un bindRequest
            return msg['protocolOp'].getName() == 'bindRequest'

        # Si los bytes no encajan, el paquete no es LDAP
        except:
            return False


    @staticmethod
    def info_bindrequest(data: bytes) -> tuple[str, str, str, str]:
        """
        Extrae informacion de un paquete LDAP BindRequest.

        Args:
            data: Paquete de red LDAP bindRequest del que se extrae la información (formato bytes).

        Returns:
            tuple: Tupla con la siguiente información (IP origen, IP destino, DN, Contraseña).
        """

        # Otro formato de paquete de scapy para obtener las IPs
        pkt = Ether(data)

        # IPs origen y destino
        ip_origen = pkt[IP].src
        ip_destino = pkt[IP].dst

        # Calculo del offset y bytes de la capa LDAP
        offset = data.find(b'\x30')
        ldap = data[offset:]

        # Capa LDAP parseada
        msg, _ = decoder.decode(ldap, asn1Spec=LDAPMessage())

        # Contenido bindRequest del paquete
        bind = msg['protocolOp']['bindRequest']

        # DN
        dn = str(bind['name'])

        # Metodo de autenticacion
        auth = bind['authentication']

        # Autenticacion con contrasegna
        if auth.getName() == 'simple':
            password = bytes(auth['simple']).decode()

        # Otros metodos de autenticacion
        else:
            password = ''

        return ip_origen, ip_destino, dn, password


    @staticmethod
    def filtrar_paquetes(captura: str, dict_dns: dict, resolver_dns: bool, verbose: bool, writer_output: TextIOWrapper = None, writer_captura: PcapWriter = None) -> None:
        """
        Filtra los bindRequests de 'captura' (formato pcap) y opcionalmente escribe la info extraida de los LDAP BindRequests (fichero, stdout, captura).

        Args:
            captura: Path al fichero de captura.
            dict_dns: Diccionario con las direcciones IP inversamente resueltas {IP: DNS}.
            resolver_dns: Booleano para realizar resolución inversa de nombres DNS.
            verbose: Booleano para ver por salida estándar la información extraída de los paquetes de red LDAP bindRequests.
            writer_output: Flujo para escribir la información extraída en un fichero de texto plano.
            writer_captura: Flujo para escribir los paquetes de red en un fichero captura de tráfico.
        """

        # Se itera sobre los paquetes de la captura
        for paquete, _ in RawPcapReader(captura):

            # Si el paquete es un LDAP bindRequest, se extrae su informacion y se escribe
            if Trafico.es_bind_request(paquete):

                # Escribir opcionalmente el paquete en una captura de trafico
                if writer_captura is not None:
                    writer_captura.write(Ether(paquete))

                # Se extrae la info del bindRequest
                ip_s, ip_d, nombre, passwd = Trafico.info_bindrequest(paquete)

                # Resolucion inversa de DNS opcional 
                if resolver_dns:
                    ip_s = rev_dns.resolver(ip_s, dict_dns)
                    ip_d = rev_dns.resolver(ip_d, dict_dns)

                # Informacion a guardar
                s = f'{ip_s}:{ip_d}:{nombre}:{passwd}'

                # Escribir la informacion en un fichero
                if writer_output is not None:
                    writer_output.write(f'{s}\n')

                # Escribir la informacion por pantalla
                if verbose:
                    print(s)
    

    @staticmethod
    def unir_dos_capturas(captura1: str, captura2: str, writer_output: TextIOWrapper, dict_dns: dict, resolver_dns: bool, verbose: bool) -> None:
        """
        Añade los bindRequests de la segunda captura de tráfico a la primera y borra la segunda.

        Args:
            captura1: Path al primer fichero de captura.
            captura1: Path al segundo fichero de captura.
            writer_output: Flujo para escribir la información extraída en un fichero de texto plano.
            dict_dns: Diccionario con las direcciones IP inversamente resueltas {IP: DNS}.
            resolver_dns: Booleano para realizar resolución inversa de nombres DNS.
            verbose: Booleano para ver por salida estándar la información extraída de los paquetes de red LDAP bindRequests.
        """

        # Escritor en modo append para no sobreescribir los paquetes ya existentes
        writer_captura = PcapWriter(captura1, append=True, sync=True)

        # Se filtran los paquetes LDAP BindRequest de la nueva captura recogida y se fusionan con los que ya se han filtrado
        Trafico.filtrar_paquetes(captura2, dict_dns, resolver_dns, verbose, writer_output, writer_captura)

        # Eliminar la segunda captura (sus paquetes ya se han fusionado con todos los anteriores)
        os.remove(captura2)

        # Se cierra el escritor
        writer_captura.close()


    @staticmethod
    def filtrar_ldap_primera_captura(captura: str, writer_output: TextIOWrapper, dict_dns: dict, resolver_dns: bool, verbose: bool) -> None:
        """
        Extrae los bindRequests de una captura de tráfico en formato pcap y la sobreescribe, dejando exclusivamente estos paquetes.

        Args:
            captura: Path al fichero de captura.
            writer_output: Flujo para escribir la información extraída en un fichero de texto plano.
            dict_dns: Diccionario con las direcciones IP inversamente resueltas {IP: DNS}.
            resolver_dns: Booleano para realizar resolución inversa de nombres DNS.
            verbose: Booleano para ver por salida estándar la información extraída de los paquetes de red LDAP bindRequests.
        """

        # Si ya existe localmente una captura de trafico con ese nombre, se sobreescribe para evitar conflictos
        if os.path.isfile(captura):
            os.remove(captura)

        # Escritor del fichero de captura
        writer_captura = PcapWriter(captura, sync=True)

        nombre_temporal = f'{captura}_temp'

        # Se filtran los paquetes LDAP BindRequest de la primera captura recogida (con nombre 'temp') y se escriben en la captura permanente
        Trafico.filtrar_paquetes(nombre_temporal, dict_dns, resolver_dns, verbose, writer_output, writer_captura)

        # Se borra la captura temporal
        os.remove(nombre_temporal)

        # Se cierra el escritor
        writer_captura.close()


    @staticmethod
    def es_pcap(captura: str) -> bool:
        """
        Analiza el formato de un fichero de captura de red.

        Args:
            captura: Path al fichero de captura.

        Returns:
            bool: True si el fichero de captura de red está en formato pcap, False en caso contrario.
        """

        # Se toman los primeros 4 bytes del fichero para ver su formato
        with open(captura, "rb") as f:
            bytes = f.read(4)

        # Magic bytes del formato de captura pcapng
        # return bytes == b'\x0a\x0d\x0d\x0a'

        # Magic bytes del formato de captura pcap
        return bytes == b'\xd4\xc3\xb2\xa1' or bytes == b'\xa1\xb2\xc3\xd4'


    @staticmethod
    def convertir_si_necesario(captura: str) -> None:
        """
        Sobreescribe el fichero a formato pcap si no lo es. REQUIERE DE EDITCAP INSTALADO Y EN VARIABLE DE ENTORNO PATH.

        Args:
            captura: Path al fichero de captura.
        """

        if not Trafico.es_pcap(captura):
            os.system(f'editcap{'.exe' if os.name == 'nt' else ''} -F pcap {captura} {captura}')
