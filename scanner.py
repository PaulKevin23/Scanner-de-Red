import os
import socket
from dotenv import load_dotenv
from scapy.all import ARP, Ether, srp, conf
from supabase import create_client, Client


# 1. Cargar credenciales desde el archivo .env
load_dotenv()
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

def obtener_subred_local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)) 
        ip_local = s.getsockname()[0]
    finally:
        s.close()
    partes = ip_local.split('.')
    return f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"

def scan_network(ip_range):
    print(f"Escaneando la red: {ip_range}...")
    
    # Asegura que Scapy use la interfaz predeterminada del sistema
    interfaz = conf.iface
    print(f"Interfaz utilizada por Scapy: {interfaz.name if hasattr(interfaz, 'name') else interfaz}")

    # Crear paquete ARP broadcast
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # timeout=4 y retry=1 para dar tiempo a que los nodos de la malla respondan
    ans, _ = srp(packet, timeout=4, retry=1, verbose=0, iface=interfaz)
    
    devices = []
    for sent, received in ans:
        devices.append({
            'ip_address': received.psrc,
            'mac_address': received.hwsrc,
            'status': 'online'
        })
    return devices

def update_database(devices):
    print(f"Se encontraron {len(devices)} dispositivos. Sincronizando con Supabase...")
    for dev in devices:
        # Upsert: Inserta si la MAC es nueva, actualiza si ya existe
        response = supabase.table('devices').upsert(dev, on_conflict='mac_address').execute()
        print(f"Registrado -> IP: {dev['ip_address']} | MAC: {dev['mac_address']}")

if __name__ == "__main__":
    # IMPORTANTE: Ajusta este rango según tu red local (ej. 192.168.0.1/24 o 192.168.1.1/24)
    target_ip = obtener_subred_local()
    print(f"Red principal detectada automáticamente: {target_ip}")

    found_devices = scan_network(target_ip)
    
    if found_devices:
        update_database(found_devices)
        print("Sincronización completada.")
    else:
        print("No se encontraron dispositivos de Red. Verifica tu rango de IP o permisos de red.")