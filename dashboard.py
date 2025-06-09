import altair as alt
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
import streamlit as st


# =====================================
#   Carga de datos
# =====================================

# Cargar nombres de columnas
features_path = r'.\CSV Files\NUSW-NB15_features.csv'
features_df = pd.read_csv(features_path, encoding='latin1')
features_df.columns = features_df.columns.str.strip()

# Crear diccionario de conversión de tipos
type_mapping = {
    'Float': 'float32',
    'Integer': 'Int64',
    'integer': 'Int64',
    'Binary': 'Int8',
    'binary': 'Int8',
    'nominal': 'category',
    'Timestamp': 'str'
}

# Crear diccionario que asocie cada nombre de la columna (clave) con su tipo de datos (valor)
dtype_dict = {}
for index, row in features_df.iterrows():
    column_name = row['Name']
    column_type = type_mapping.get(row['Type'], 'object')
    dtype_dict[column_name] = column_type

# Archivos de datos sin encabezado
data_files = [
    r'.\CSV Files\UNSW-NB15_1.csv',
    r'.\CSV Files\UNSW-NB15_2.csv',
    r'.\CSV Files\UNSW-NB15_3.csv',
    r'.\CSV Files\UNSW-NB15_4.csv'
]

# Leer y concatenar todos los archivos
dataframes = []
for file in data_files:
    # Leer archivo sin asignar tipos
    df = pd.read_csv(file, header=None, names=list(dtype_dict.keys()), encoding='latin1')
    dataframes.append(df)

# Concatenar los DataFrames
full_data = pd.concat(dataframes, ignore_index=True)


# =====================================
#   Limpieza y asignación de tipos
# =====================================

# Función para convertir un valor en hexadecimal a decimal y ' ' o '-' a -1
def convert_to_int(value):
    try:
        str_value = str(value).strip()
    
        if str_value.startswith('0x'): # Hexadecimal
            return int(str_value, 16)
        elif str_value in ['', '-']:
            return None
        else:
            return int(str_value)
    except ValueError:
        return value


# Aplicar la conversión a enteros
for column, dtype in dtype_dict.items():
    if dtype == 'Int64':
        full_data[column] = full_data[column].apply(convert_to_int)

# Convertir las columnas al tipo correcto según el dtype_dict
for column, dtype in dtype_dict.items():
    full_data[column] = full_data[column].astype(dtype)

# Limpiar espacios en columnas tipo category
for col in full_data.select_dtypes(['category']).columns:
    full_data[col] = full_data[col].str.strip().astype('category')

# Convertir las columnas Stime y Ltime a numéricas
full_data['Stime'] = pd.to_numeric(full_data['Stime'], errors='coerce')
full_data['Ltime'] = pd.to_numeric(full_data['Ltime'], errors='coerce')

# Convertir los valores de Stime y Ltime de Unix timestamp a datetime
full_data['Stime'] = pd.to_datetime(full_data['Stime'], unit='s')
full_data['Ltime'] = pd.to_datetime(full_data['Ltime'], unit='s')

# Renombrar Backdoors como Backdoor para estandarizar categorias
full_data['attack_cat'] = full_data['attack_cat'].replace({'Backdoors': 'Backdoor'})
full_data['service'] = full_data['service'].replace({'-': 'unknown'})


# =====================================
#   GRÁFICO 1: Gráfico circular de porceentajes de tráfico Normal vs Malicioso
# =====================================
def chart1(palette):
    malicious_ratio = full_data['Label'].mean() * 100
    normal_ratio = 100 - malicious_ratio

    ratio_df = pd.DataFrame({
        'type': ['Normal', 'Malicious'],
        'percentage': [normal_ratio, malicious_ratio]
    })

    chart = alt.Chart(ratio_df).mark_arc().encode(
        theta='percentage:Q',
        color=alt.Color('type:N', scale=alt.Scale(range=palette[:2]), legend=alt.Legend(title="Tipo de tráfico")),
        tooltip=['type:N', 'percentage:Q']
    ).properties(
        title='Porcentaje de tráfico malicioso vs normal'
    )
    return chart


# =====================================
#   GRÁFICO 2: Tabla resumen con conteo de conexiones por día y tipo de tráfico
# =====================================
def chart2(palette):
    connections_label = full_data.groupby([full_data['Stime'].dt.date, 'Label']).size().reset_index(name='count')
    connections_label['Label'] = connections_label['Label'].map({0: 'Normal', 1: 'Malicioso'})

    # Tabla resumen pivotada
    summary = connections_label.pivot_table(
        index='Stime',
        columns='Label',
        values='count',
        aggfunc='sum',
        fill_value=0
    ).reset_index()
    summary = summary.rename(columns={'Stime': 'Fecha'})
    return summary


# =====================================
#   GRÁFICO 3: Top 10 Categorías de Ataque
# =====================================
def chart3(palette):
    attack_cat_count = full_data[full_data['Label'] == 1]['attack_cat'].value_counts().nlargest(10).reset_index()
    attack_cat_count.columns = ['attack_cat', 'count']

    attack_chart = alt.Chart(attack_cat_count).mark_bar().encode(
        x=alt.X('count:Q', title='Número de ataques'),
        y=alt.Y('attack_cat:N', sort='-x', title='Categoría de ataque'),
        color=alt.Color('attack_cat:N', legend=None),
        tooltip=['attack_cat:N', 'count:Q']
    ).properties(
        title='Top 10 categorías de ataque'
    )
    return attack_chart


# =====================================
#   GRÁFICO 4: Top 10 Protocolos más usados
# =====================================
def chart4(palette, data):
    proto_count = data['proto'].value_counts().reset_index()
    proto_count.columns = ['proto', 'count']

    # Separar top 10
    top_proto = proto_count.nlargest(10, 'count')

    # Top 10 protocolos, barras horizontales
    top_chart = alt.Chart(top_proto).mark_bar().encode(
        y=alt.Y('proto:N', sort='-x', title='Protocolo'),
        x=alt.X('count:Q', title='Número de conexiones'),
        color='proto:N',
        tooltip=['proto:N', 'count:Q']
    ).properties(title='Top 10 protocolos más usados')

    return top_chart

# =====================================
#   GRÁFICO 5: Top 10 Servicios más usados
# =====================================
def chart5(palette, data):
    service_count = data['service'].value_counts().nlargest(10).reset_index()
    service_count.columns = ['service', 'count']

    service_chart = alt.Chart(service_count).mark_bar().encode(
        x=alt.X('count:Q', title='Número de conexiones'),
        y=alt.Y('service:N', sort='-x', title='Servicio'),
        color='service:N',
        tooltip=['service:N', 'count:Q']
    ).properties(
        title='Top 10 servicios utilizados'
    )
    return service_chart

# =====================================
#   GRÁFICO 6: IPs origen y destino con tráfico malicioso
# =====================================
def chart6(palette):
    # Filtrar tráfico malicioso
    malicious_data = full_data[full_data['Label'] == 1]

    # IPs origen más activas (con observed=True para evitar el warning)
    top_src_ips = malicious_data.groupby(['srcip', 'attack_cat'], observed=True).size().reset_index(name='count')

    top_src_ips_chart = alt.Chart(top_src_ips).mark_bar().encode(
        y=alt.Y('srcip:N', sort='-x', title='IP Origen'),
        x=alt.X('count:Q', title='Número de Conexiones'),
        color=alt.Color('attack_cat:N', title='Categoría de Ataque'),
        tooltip=['srcip:N', 'attack_cat:N', 'count:Q']
    ).properties(
        title='IPs de Origen más Activas por Categoría de Ataque'
    ).transform_filter(
        alt.datum.count > 10
    )

    # IPs destino más activas (con observed=True también)
    top_dst_ips = malicious_data.groupby(['dstip', 'attack_cat'], observed=True).size().reset_index(name='count')

    top_dst_ips_chart = alt.Chart(top_dst_ips).mark_bar().encode(
        y=alt.Y('dstip:N', sort='-x', title='IP Destino'),
        x=alt.X('count:Q', title='Número de Conexiones'),
        color=alt.Color('attack_cat:N', title='Categoría de Ataque'),
        tooltip=['dstip:N', 'attack_cat:N', 'count:Q']
    ).properties(
        title='IPs de Destino más Activas por Categoría de Ataque'
    ).transform_filter(
        alt.datum.count > 10
    )

    return top_src_ips_chart, top_dst_ips_chart


# =====================================
#   Configurar la página de Streamlit
# =====================================

st.set_page_config(
    page_title="Dashboard de Seguridad en Red",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Paleta de colores para ciberseguridad
security_palette = ['#1f2937', '#10b981', '#2563eb', '#f59e42', '#f43f5e', '#64748b']

# Título principal
st.title("Análisis de Seguridad en Tráfico de Red")
st.subheader("Visualización interactiva de tráfico normal y malicioso")

# Tabs principales
tab1, tab2, tab3 = st.tabs([
    "Visión General del Tráfico de Red",
    "Análisis del Tráfico Malicioso",
    "Análisis de Rendimiento y Efectos del Ataque"
])

with tab1:
    st.header("Visión General del Tráfico de Red")
    st.write("El objetivo de este panel es ofrecer una panorámica rápida del volumen, distribución y tipo de tráfico observado.")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.write("**Conteo de conexiones por día y tipo**")
        st.dataframe(chart2(security_palette), use_container_width=True, hide_index=True)
    with col2:
        st.altair_chart(chart1(security_palette), use_container_width=True)
    with col3:
        st.altair_chart(chart3(security_palette), use_container_width=True)
    
    st.markdown("### Top 10 protocolos y servicios")
    col4, _ = st.columns([2, 1])
    with col4:
        chart4_chart5_filter = st.radio(
            "Selecciona el tipo de tráfico para los gráficos:",
            ("Todo", "Normal", "Malicioso"),
            index=0,
            horizontal=True,
            key="proto_filter"
        )
        if chart4_chart5_filter == "Malicioso":
            df_c4_c5 = full_data[full_data['Label'] == 1]
        elif chart4_chart5_filter == "Normal":
            df_c4_c5 = full_data[full_data['Label'] == 0]
        else:
            df_c4_c5 = full_data

    col5, col6 = st.columns([1, 1])
    with col5:
        st.altair_chart(chart4(security_palette, df_c4_c5), use_container_width=True)
    with col6:
        st.altair_chart(chart5(security_palette, df_c4_c5), use_container_width=True)

with tab2:
    st.header("Análisis del Tráfico Malicioso")
    st.write("Próximamente: análisis detallado del tráfico malicioso.")

with tab3:
    st.header("Análisis de Rendimiento y Efectos del Ataque")
    st.write("Próximamente: métricas de rendimiento y efectos de los ataques en la red.")