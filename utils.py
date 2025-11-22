
import sys, os
from scapy.all import IP, RawPcapReader, Ether
from pyasn1.codec.ber import decoder
from pyasn1_ldap.rfc4511 import LDAPMessage


""" Finaliza la ejecucion del programa con un mensaje de error y un codigo de salida """
def soltar_error(mensaje, codigo):
    print(f'\n[!] {mensaje}\n')
    sys.exit(codigo)



""" Devuelve True si un paquete (formato bytes) es un LDAP bindRequest """
def es_bind_request(data):
    try:
        # Se calcula el offset a partir del cual empieza la capa LDAP
        offset = data.find(b'\x30')

        # Bytes de la capa LDAP
        ldap = data[offset:]

        # Capa LDAP parseada
        msg, _ = decoder.decode(ldap, asn1Spec=LDAPMessage())

        return msg['protocolOp'].getName() == 'bindRequest'

    # Si los bytes no encajan, el paquete no es LDAP
    except Exception:
        return False



""" Extrae informacion (IP origen, IP destino, dn y contraseña) de un paquete LDAP BindRequest """
def info_bindrequest(data):
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



""" Filtra los bindRequests de 'captura' (formato pcap) y escribe la info (fichero o stdout). Opcionalmente escribe los bindRequests en una captura de trafico """
def filtrar_paquetes(captura, writer_output = None, writer_captura = None):
    for paquete, _ in RawPcapReader(captura):
        # Si el paquete es un LDAP bindRequest, se extrae su informacion
        if es_bind_request(paquete):
            ip_s, ip_d, nombre, passwd = info_bindrequest(paquete)
            
            # Escribir opcionalmente el paquete en una captura de trafico
            if writer_captura is not None:
                writer_captura.write(Ether(paquete))

            s = f'{ip_s}:{ip_d}:{nombre}:{passwd}'

            # Escribir opcionalmente la informacion en un fichero de texto plano o por pantalla
            if writer_output is not None:
                writer_output.write(f'{s}\n')
            else:
                print(s)



""" Devuelve True si el fichero es una captura de trafico con formato pcap """
def es_pcap(captura):
    with open(captura, "rb") as f:
        bytes = f.read(4)

    # return magic == b'\x0a\x0d\x0d\x0a' # Formato pcapng
    return bytes == b'\xd4\xc3\xb2\xa1' or bytes == b'\xa1\xb2\xc3\xd4'



""" Sobreescribe el fichero a formato pcap si no lo es """
def convertir_si_necesario(captura):
    if not es_pcap(captura):
        os.system(f'editcap{'' if os.name == 'posix' else '.exe'} -F pcap {captura} {captura}')
