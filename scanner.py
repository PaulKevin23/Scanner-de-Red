import os
from dotenv import load_dotenv
from scapy.all import ARP, Ether, srp, conf
from supabase import create_client, Client

load_dotenv()
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

def obtener_config_red_automatica():
    # Scapy determina la interfaz activa y la IP local consultando la ruta principal
    interfaz, _, ip_local = conf.route.route("8.8.8.8")
    
    # Convierte la IP (ej. 192.168.1.91) en formato de subred (192.168.1.0/24)
    partes = ip_local.split('.')
    subred = f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"
    
    return subred, interfaz

def scan_network(ip_range, interfaz):
    print(f"Escaneando la red: {ip_range} mediante {interfaz.name}...")
    
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # retry=2 aumenta la tolerancia para no perder dispositivos en redes Wi-Fi lentas
    ans, _ = srp(packet, timeout=3, retry=2, verbose=0, iface=interfaz)
    
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
        response = supabase.table('devices').upsert(dev, on_conflict='mac_address').execute()
        print(f"Registrado -> IP: {dev['ip_address']} | MAC: {dev['mac_address']}")

if __name__ == "__main__":
    target_ip, iface = obtener_config_red_automatica()
    print(f"Subred detectada: {target_ip} | Interfaz activa: {iface.name}")

    found_devices = scan_network(target_ip, iface)
    
    if found_devices:
        update_database(found_devices)
        print("Sincronización completada.")
    else:
        print("No se encontraron dispositivos. Verifica la conexión o permisos.")