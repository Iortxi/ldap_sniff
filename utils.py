
import sys, os, rev_dns
from scapy.all import IP, RawPcapReader, Ether
from pyasn1.codec.ber import decoder
from pyasn1_ldap.rfc4511 import LDAPMessage


def soltar_error(mensaje: str, codigo: int):
    """ Finaliza la ejecucion del programa con un mensaje de error y un codigo de salida """

    print(f'\n[!] {mensaje}\n')
    sys.exit(codigo)



def es_bind_request(data: bytes) -> bool:
    """ Devuelve True si un paquete (formato bytes) es un LDAP bindRequest """

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



def info_bindrequest(data: bytes) -> tuple[str, str, str, str]:
    """ Extrae informacion (IP origen, IP destino, dn y contraseña) de un paquete LDAP BindRequest (formato bytes) """

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



def filtrar_paquetes(captura: str, dict_dns: dict, resolver_dns: bool, verbose: bool, writer_output, writer_captura = None):
    """ Filtra los bindRequests de 'captura' (formato pcap) y opcionalmente escribe la info extraida de los LDAP BindRequests (fichero, stdout, captura) """

    # Se itera sobre los paquetes de la captura
    for paquete, _ in RawPcapReader(captura):

        # Si el paquete es un LDAP bindRequest, se extrae su informacion y se escribe
        if es_bind_request(paquete):

            # Escribir opcionalmente el paquete en una captura de trafico
            if writer_captura is not None:
                writer_captura.write(Ether(paquete))

            # Se extrae la info del bindRequest
            ip_s, ip_d, nombre, passwd = info_bindrequest(paquete)

            # Resolucion inversa de DNS opcional 
            if resolver_dns:
                ip_s = rev_dns.resolver(ip_s, dict_dns)
                ip_d = rev_dns.resolver(ip_d, dict_dns)

            # Informacion a guardar
            s = f'{ip_s}:{ip_d}:{nombre}:{passwd}'

            # Escribir opcionalmente la informacion en un fichero o por pantalla
            if writer_output is not None:
                writer_output.write(f'{s}\n')
            elif verbose:
                print(s)



def es_pcap(captura: str):
    """ Devuelve True si el fichero es una captura de trafico con formato pcap """

    # Se toman los primeros 4 bytes del fichero para ver su formato
    with open(captura, "rb") as f:
        bytes = f.read(4)

    # Magic bytes del formato de captura pcapng
    # return bytes == b'\x0a\x0d\x0d\x0a'

    # Magic bytes del formato de captura pcap
    return bytes == b'\xd4\xc3\xb2\xa1' or bytes == b'\xa1\xb2\xc3\xd4'



def convertir_si_necesario(captura: str):
    """ Sobreescribe el fichero a formato pcap si no lo es. REQUIERE DE EDITCAP INSTALADO Y EN VARIABLE DE ENTORNO PATH """

    if not es_pcap(captura):
        os.system(f'editcap{'.exe' if os.name == 'nt' else ''} -F pcap {captura} {captura}')
