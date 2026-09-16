import os
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from supabase import create_client, Client

# Configurar la página web
st.set_page_config(
    page_title="Dashboard de Red - Supabase",
    page_icon="🌐",
    layout="wide"
)

# Cargar credenciales desde el archivo .env existente
load_dotenv()
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")

@st.cache_resource
def init_connection():
    return create_client(url, key)

supabase = init_connection()

# Título principal del Dashboard
st.title("🛡️ Panel de Control de Dispositivos en Red")
st.markdown("Monitoreo en tiempo real de los equipos conectados sincronizados con Supabase.")

# Botón para actualizar los datos manualmente
if st.button("🔄 Refrescar Datos"):
    st.rerun()

# Obtener los datos de la tabla 'devices' en Supabase
@st.cache_data(ttl=10)
def fetch_data():
    response = supabase.table("devices").select("*").execute()
    return response.data

data = fetch_data()

if data:
    df = pd.DataFrame(data)
    
    # Métricas superiores rápidas
    total_dispositivos = len(df)
    st.metric(label="Dispositivos Totales Registrados", value=total_dispositivos)
    
    # Mostrar la tabla interactiva
    st.subheader("📋 Listado de Equipos")
    st.dataframe(df, use_container_width=True)
else:
    st.warning("No hay dispositivos registrados todavía. Ejecuta tu script scanner.py para poblar la base de datos.")