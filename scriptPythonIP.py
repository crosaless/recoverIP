import pyshark

# Cargar el archivo de captura pcapng
file_path = 'C:/Users/Cristian/Documents/datos_de_conexion_google.pcapng' 

# Cargar la captura utilizando pyshark
capture = pyshark.FileCapture(file_path)

# Filtrar las conexiones UDP desde 192.168.10.102 al servidor de Google
udp_connections = []
udp_connections_google = []

for packet in capture:
    # Verificar que sea un paquete UDP
    if 'UDP' in packet:
        # Verificar si la IP de origen es 192.168.10.102
        if packet.ip.src == '192.168.10.102':
            udp_connections.append(packet)
            break

# Extraer información de la primera conexión UDP desde 192.168.10.102
if udp_connections:
    first_udp_conn = udp_connections[0]
    first_udp_conn_info = {
        'Source IP': first_udp_conn.ip.src,
        'Destination IP': first_udp_conn.ip.dst,
        'Source Port': first_udp_conn.udp.srcport,
        'Destination Port': first_udp_conn.udp.dstport,
        'UDP Length': first_udp_conn.udp.length,
        'UDP checksum': first_udp_conn.udp.checksum,
        'Info': first_udp_conn.sniff_time
    }
    print("Información de la primera conexión UDP desde 192.168.10.102:")
    for key, value in first_udp_conn_info.items():
        print(f"{key}: {value}")
else:
    first_udp_conn_info = "No UDP connection found from 192.168.10.102"

#ahora busco la ultima conexión UDP desde 142.250.79.110

for packet in capture:
    if 'UDP' in packet:
        if packet.ip.src == '142.250.79.110':
            udp_connections_google.append(packet)
            break

#extraigo la informacion de la ultima rta de google
if udp_connections_google:
    last_udp_conn_google = udp_connections_google[-1]
    last_udp_conn_google_info = {
        'Source IP': last_udp_conn_google.ip.src,
        'Destination IP': last_udp_conn_google.ip.dst,
        'Source Port': last_udp_conn_google.udp.srcport,
        'Destination Port': last_udp_conn_google.udp.dstport,
        'UDP Length': last_udp_conn_google.udp.length,
        'UDP checksum': last_udp_conn_google.udp.checksum,
        'Info': last_udp_conn_google.sniff_time
    }
    print("Información de la última conexión UDP desde Google:")
    for key, value in last_udp_conn_google_info.items():
        print(f"{key}: {value}")
else:
    last_udp_conn_google_info = "No UDP connection found from Google"

