import os
from dotenv import load_dotenv
from scapy.all import ARP, Ether, srp, conf
from supabase import create_client, Client

# 1. Cargar credenciales desde el archivo .env
load_dotenv()
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

def obtener_config_red_automatica():
    # Scapy determina la interfaz activa y la IP local consultando la ruta principal
    interfaz, _, ip_local = conf.route.route("8.8.8.8")
    
    # Manejo seguro por si la interfaz se devuelve como texto o como objeto
    nombre_interfaz = interfaz if isinstance(interfaz, str) else getattr(interfaz, 'name', 'Desconocida')
    
    # Convierte la IP local en formato de subred (ej. 192.168.1.0/24)
    partes = ip_local.split('.')
    subred = f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"
    
    return subred, interfaz, nombre_interfaz

def scan_network(ip_range, interfaz):
    print(f"Escaneando la red: {ip_range} mediante la interfaz activa...")
    
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # retry=2 aumenta la tolerancia para no perder dispositivos en redes dinámicas
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
        # Upsert: Inserta si la MAC es nueva, actualiza si ya existe
        response = supabase.table('devices').upsert(dev, on_conflict='mac_address').execute()
        print(f"Registrado -> IP: {dev['ip_address']} | MAC: {dev['mac_address']}")

if __name__ == "__main__":
    target_ip, iface, nombre_iface = obtener_config_red_automatica()
    print(f"Subred detectada: {target_ip} | Interfaz activa: {nombre_iface}")

    found_devices = scan_network(target_ip, iface)
    
    if found_devices:
        update_database(found_devices)
        print("Sincronización completada.")
    else:
        print("No se encontraron dispositivos. Verifica la conexión o permisos.")