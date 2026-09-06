import os
from dotenv import load_dotenv
from scapy.all import ARP, Ether, srp
from supabase import create_client, Client

# 1. Cargar credenciales desde el archivo .env
load_dotenv()
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

def scan_network(ip_range):
    print(f"Escaneando la red: {ip_range}...")
    # Crear paquete ARP para buscar dispositivos en la red
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Enviar el paquete y recibir respuestas (timeout de 3 segundos)
    result = srp(packet, timeout=3, verbose=0)[0]
    
    devices = []
    for sent, received in result:
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
    target_ip = "192.168.1.1/24" 
    
    found_devices = scan_network(target_ip)
    
    if found_devices:
        update_database(found_devices)
        print("Sincronización completa.")
    else:
        print("No se encontraron dispositivos. Verifica tu rango de IP o permisos de red.")