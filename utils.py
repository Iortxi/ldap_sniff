
import sys, os
from scapy.all import TCP, IP, RawPcapReader, Ether

"""
POSIBLE MEJORA: TENER EN CUENTA SOLO LAS CONTRASEÑAS VALIDAS, NO LAS INCORRECTAS
POSIBLE IDEA: DICCIONARIO DE USUARIOS QUE HAN ABIERTO UN BINDREQUEST, Y CUANDO SE VEA UN BINDRESPONSE, SE COMPRUEBE SI SE TIENE UNA ENTRADA CON ESE USUARIO

S1 -> S2 - bindRequest (con la pass)

si ok -> bindResponse OK
si no ok -> bindResponse NO OK
NO CREO QUE SE PUEDA, A VECES NO SE RECOGE EL BINDRESPONSE

------------------------------------------------------------------------------------------------------------------------

POSIBLE MEJORA: HACER RESOLUCIONES INVERSAS DE DNS CON LAS IPs, Y SI NO SON EXITOSAS, PONER SOLO LA IP
UTILIZAR DICCIONARIO (IP:NOMBRE) PARA NO REPETIR CONSULTAS
import dns.resolver
import dns.reversename
def reverse_dns(ip, timeout=2.0):
    try:
        rev_name = dns.reversename.from_address(ip)

        # Resolver con timeout personalizado
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        respuesta = resolver.resolve(rev_name, "PTR")

        # Tomamos el primer nombre y quitamos el punto final
        nombre = respuesta[0].to_text().rstrip('.')
        return nombre

    except Exception:
        # Si falla por timeout, NXDOMAIN, etc., devolver la IP original
        return ip
"""



""" Finaliza la ejecucion del programa con un mensaje de error y un codigo de estado """
def soltar_error(mensaje, codigo):
    print(f'\n[!] {mensaje}\n')
    sys.exit(codigo)



""" Extrae el nombre y la contraseña (simple bind) de un paquete LDAP BindRequest """
def parsear_ldap_bind(payload):
    try:
        idx = payload.index(0x60)  # BindRequest start
        cursor = idx + 2  # Skip 0x60 and length byte

        # Skip version (usually 0x02 0x01 0x03 for version 3)
        if payload[cursor] == 0x02:
            cursor += 2  # tag + length
            cursor += 1  # skip version value

        # Extract name (LDAPDN, usually an Octet String - tag 0x04)
        nombre = ""
        if payload[cursor] == 0x04:
            name_len = payload[cursor + 1]
            name_bytes = payload[cursor + 2:cursor + 2 + name_len]
            nombre = name_bytes.decode(errors="ignore")
            cursor = cursor + 2 + name_len

        # Extract simple password (tag 0x80)
        password = ""
        if payload[cursor] == 0x80:
            pwd_len = payload[cursor + 1]
            pwd_bytes = payload[cursor + 2:cursor + 2 + pwd_len]
            password = pwd_bytes.decode(errors="ignore")

        return nombre, password

    except:
        return None, None



""" Devuelve True, IP origen, IP destino, usuario, password si 'pkt' es un LDAP bindRequest """
def paquete_ldap_bind_request(pkt):
    if IP in pkt and TCP in pkt and pkt[TCP].payload and pkt[TCP].dport == 389:
        raw = bytes(pkt[TCP].payload)
        if len(raw) > 0 and 0x60 in raw and raw[0] == 0x30:
            nombre, passwd = parsear_ldap_bind(raw)
            return nombre and passwd, pkt[IP].src, pkt[IP].dst, nombre, passwd
    return False, None, None, None, None



""" Filtra los bindRequests de 'captura' (formato pcap) y escribe la info (fichero o stdout). Opcionalmente escribe los bindRequests en una captura de trafico """
def filtrar_paquetes(captura, writer_output = None, writer_captura = None):
    for paquete, _ in RawPcapReader(captura):
        pkt = Ether(paquete)
        es_bind_request, ip_s, ip_d, nombre, passwd = paquete_ldap_bind_request(pkt)
        if es_bind_request:
            if writer_captura is not None:
                writer_captura.write(pkt)
            
            s = f'{ip_s}:{ip_d}:{nombre}:{passwd}'

            if writer_output is not None:
                writer_output.write(f'{s}\n')
            else:
                print(s)



""" Devuelve True si el fichero es una captura de trafico con formato pcap """
def es_pcap(captura):
    with open(captura, "rb") as f:
        bytes = f.read(4)

    # return magic == b'\x0a\x0d\x0d\x0a' # pcapng en teoria
    return bytes == b'\xd4\xc3\xb2\xa1' or bytes == b'\xa1\xb2\xc3\xd4'



""" Sobreescribe el fichero a formato pcap si no lo es """
def convertir_si_necesario(captura):
    if not es_pcap(captura):
        os.system(f'editcap{'' if os.name == 'posix' else '.exe'} -F pcap {captura} {captura}')
