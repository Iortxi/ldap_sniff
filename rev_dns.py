
import dns.resolver
from collections import deque

# Public DNS servers
dns_servers = ['8.8.8.8', '8.8.4.4',                    # Google
                '74.82.42.42',                          # Hurricane Electric
                '76.76.2.0', '76.76.10.0',              # Control D
                '9.9.9.9', '149.112.112.112',           # Quad9
                '94.140.14.14', '94.140.15.15',         # AdGuard DNS
                '208.67.222.222', '208.67.220.220',     # OpenDNS Home
                '185.228.168.9', '185.228.169.9',       # CleanBrowsing
                '76.76.19.19', '76.223.122.150',        # Alternate DNS

                # Cloudflare
                '1.1.1.3', '1.1.1.2',
                '1.1.1.1', '1.0.0.3',
                '1.0.0.2', '1.0.0.1',]

# Cola circular de servidores DNS
dns_servers = deque(dns_servers)



def resolver(ip: str, dict: dict) -> str:
    """
    Resuelve inversamente una IP y devuelve su nombre DNS, si no se puede, se devuelve la IP.

    Args:
        ip: Cadena de texto con la IP en formato IPv4 a resolver inversamente.
        dict: Diccionario {IP: DNS} con las direcciones IP ya resueltas, en caso de que ya se haya procesado y no sea necesario hacerlo de nuevo.

    Returns:
        str: Cadena de texto con el nombre DNS obtenido de la resolucion inversa, la misma IP en caso de que la resolucion inversa no haya dado resultados.
    """

    global dns_servers
    try:
        # La IP ya esta resuelta o ya se ha visto que no existe
        if ip in dict:
            return dict[ip]
        
        # Objeto resolvedor DNS
        resolver = dns.resolver.Resolver()
        resolver.nameservers = list(dns_servers)

        # Resolucion inversa
        rev_name = dns.reversename.from_address(ip)
        respuesta = resolver.resolve(rev_name, 'PTR')

        # Se toma el primer nombre y se le quita el punto final
        nombre = str(respuesta[0]).rstrip('.')

        # Se agnade el nombre a las IPs resueltas
        dict[ip] = nombre

    # Si la resolucion inversa falla
    except:
        # Se agnade la IP sin nombre al diccionario
        dict[ip] = ip

    finally:
        # Se rota la cola circular
        dns_servers.rotate(-1)

        # Se devuelve el nombre obtenido o la IP
        return dict[ip]
