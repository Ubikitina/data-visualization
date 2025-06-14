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

# Filtrar tráfico malicioso
malicious_data = full_data[full_data['Label'] == 1]


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
#   GRÁFICO 3: Categorías de Ataque
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
        title='Categorías de ataque'
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
#   GRÁFICO 7: Promedio de Spkts y Dpkts por tipo de ataque
# =====================================
def chart7(malicious_data, palette):
    # Calcular promedios
    spkts_mean = malicious_data.groupby('attack_cat')['Spkts'].mean().reset_index()
    dpkts_mean = malicious_data.groupby('attack_cat')['Dpkts'].mean().reset_index()

    # Gráfico de Spkts
    chart_spkts = alt.Chart(spkts_mean).mark_bar().encode(
        x=alt.X('attack_cat:N', title='Tipo de ataque'),
        y=alt.Y('Spkts:Q', title='Promedio de paquetes enviados (Spkts)'),
        color='attack_cat:N',
        tooltip=['attack_cat:N', 'Spkts:Q']
    ).properties(
        title='Promedio de Spkts por tipo de ataque',
        width=300,
        height=300
    )

    # Gráfico de Dpkts
    chart_dpkts = alt.Chart(dpkts_mean).mark_bar().encode(
        x=alt.X('attack_cat:N', title='Tipo de ataque'),
        y=alt.Y('Dpkts:Q', title='Promedio de paquetes recibidos (Dpkts)'),
        color='attack_cat:N',
        tooltip=['attack_cat:N', 'Dpkts:Q']
    ).properties(
        title='Promedio de Dpkts por tipo de ataque',
        width=300,
        height=300
    )

    # Mostrar ambos gráficos con la escala Y compartida
    return alt.hconcat(chart_spkts, chart_dpkts).resolve_scale(y='shared')


# =====================================
#   GRÁFICO 10: Promedio de Spkts y Dpkts por tipo de ataque
# =====================================
def chart10(malicious_data, palette):
    # Calcular promedios de sloss y dloss por tipo de ataque
    sloss_mean = malicious_data.groupby('attack_cat')['sloss'].mean().reset_index()
    dloss_mean = malicious_data.groupby('attack_cat')['dloss'].mean().reset_index()

    # Gráfico de sloss
    chart_sloss = alt.Chart(sloss_mean).mark_bar().encode(
        x=alt.X('attack_cat:N', title='Tipo de ataque'),
        y=alt.Y('sloss:Q', title='Promedio de pérdida (sloss)'),
        color='attack_cat:N',
        tooltip=['attack_cat:N', 'sloss:Q']
    ).properties(
        title='Promedio de sloss por tipo de ataque',
        width=300,
        height=300
    )

    # Gráfico de dloss
    chart_dloss = alt.Chart(dloss_mean).mark_bar().encode(
        x=alt.X('attack_cat:N', title='Tipo de ataque'),
        y=alt.Y('dloss:Q', title='Promedio de pérdida (dloss)'),
        color='attack_cat:N',
        tooltip=['attack_cat:N', 'dloss:Q']
    ).properties(
        title='Promedio de dloss por tipo de ataque',
        width=300,
        height=300
    )

    # Combinar los gráficos con escala Y compartida
    return alt.hconcat(chart_sloss, chart_dloss).resolve_scale(
        y='shared'
    )


# =====================================
#   GRÁFICO 11: TPC RTT vs Syn-ACK
# =====================================
def chart11(malicious_data, palette):
    # Crear selección interactiva por categoría de ataque
    selection = alt.selection_multi(fields=['attack_cat'], bind='legend')

    rtt_scatter = alt.Chart(malicious_data).mark_circle(size=60, opacity=0.5).encode(
        x=alt.X('tcprtt:Q', title='TCP Round Trip Time'),
        y=alt.Y('synack:Q', title='Tiempo SYN-ACK'),
        color=alt.Color('attack_cat:N', title='Categoría de Ataque'),
        tooltip=['attack_cat:N', 'tcprtt:Q', 'synack:Q', 'ackdat:Q'],
        opacity=alt.condition(selection, alt.value(0.7), alt.value(0.1))
    ).add_params(
        selection
    ).properties(
        title='Relación entre TCP RTT y SYN-ACK'
    )

    return rtt_scatter




# =====================================
#   GRÁFICO 14: Función genérica gráfico facetado
# =====================================
def chart14(malicious_data, palette, attack_cat):
    # Filtrar por el ataque seleccionado
    df_filtered = malicious_data[malicious_data['attack_cat'] == attack_cat]

    # Primer grupo de variables
    variables1 = ['proto', 'service', 'state']
    # Segundo grupo de variables
    variables2 = ['sport', 'dsport', 'is_ftp_login', 'is_sm_ips_ports']

    # Melt y conteo para el primer grupo
    df_melted1 = df_filtered.melt(id_vars=['attack_cat'], value_vars=variables1,
                                  var_name='Variable', value_name='Valor')
    count_df1 = df_melted1.groupby(['Variable', 'Valor']).size().reset_index(name='count')

    pie1 = alt.Chart(count_df1).mark_arc(innerRadius=50).encode(
        theta=alt.Theta('count:Q', title='Cantidad'),
        color=alt.Color('Valor:N', legend=alt.Legend(title='Valor')),
        tooltip=[
            alt.Tooltip('Variable:N', title='Variable'),
            alt.Tooltip('Valor:N', title='Valor'),
            alt.Tooltip('count:Q', title='Cantidad'),
        ]
    ).properties(
        width=200,
        height=200
    ).facet(
        column=alt.Column('Variable:N', title='Variable', header=alt.Header(labelAngle=270), sort=variables1),
        columns=3
    ).resolve_scale(
        color='independent'
    )

    # Melt y conteo para el segundo grupo
    df_melted2 = df_filtered.melt(id_vars=['attack_cat'], value_vars=variables2,
                                  var_name='Variable', value_name='Valor')
    count_df2 = df_melted2.groupby(['Variable', 'Valor']).size().reset_index(name='count')

    pie2 = alt.Chart(count_df2).mark_arc(innerRadius=50).encode(
        theta=alt.Theta('count:Q', title='Cantidad'),
        color=alt.Color('Valor:N', legend=alt.Legend(title='Valor')),
        tooltip=[
            alt.Tooltip('Variable:N', title='Variable'),
            alt.Tooltip('Valor:N', title='Valor'),
            alt.Tooltip('count:Q', title='Cantidad'),
        ]
    ).properties(
        width=200,
        height=200
    ).facet(
        column=alt.Column('Variable:N', title='Variable', header=alt.Header(labelAngle=270), sort=variables2),
        columns=4
    ).resolve_scale(
        color='independent'
    )

    return pie1, pie2


# =====================================
#   GRÁFICO 15: Distribución de bytes por tipo de tráfico
# =====================================
def chart15(df, palette):
    cols = ['Label', 'sbytes', 'dbytes']
    df_small = df[cols]

    # Transformar a formato largo
    df_melted = pd.melt(df_small, id_vars='Label', value_vars=['sbytes', 'dbytes'],
                        var_name='Direction', value_name='Bytes')

    df_melted = df_melted.dropna(subset=['Bytes'])
    df_melted['Bytes'] = pd.to_numeric(df_melted['Bytes'], errors='coerce')

    # Crear la nueva columna para el eje x
    df_melted['Grupo'] = df_melted['Direction'] + df_melted['Label'].astype(str)

    # Muestreo para acelerar, si tienes muchos datos
    df_sampled = df_melted.sample(frac=0.2, random_state=42)

    bytes_chart = alt.Chart(df_sampled).mark_boxplot().encode(
        x=alt.X('Grupo:N', title=''),
        y=alt.Y('Bytes:Q', title='Bytes')
    ).properties(
        width=400,
        title='Distribución de bytes enviados y recibidos según tipo de tráfico'
    )

    return bytes_chart



# =====================================
#   GRÁFICO 16: Duración vs Paquetes
# =====================================
def chart16(df, palette):
    cols = ['dur', 'Spkts', 'Dpkts', 'Label']
    df_small = df[cols]

    # Muestreo para acelerar, si tienes muchos datos
    df_sampled = df_small.sample(frac=0.2, random_state=42)

    pkt_scatter = alt.Chart(df_sampled).mark_circle(size=10, opacity=0.4).encode(
        x='dur:Q',
        y='Spkts:Q',
        color=alt.Color('Label:N',
            scale=alt.Scale(domain=[0, 1], range=['blue', 'red']),
            legend=alt.Legend(title='Label')
        ),
        tooltip=['dur', 'Spkts', 'Dpkts']
    ).interactive().properties(
        title='Duración de las conexiones vs número de paquetes enviados'
    )

    return pkt_scatter



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
st.write(
    "Explora de forma interactiva el tráfico normal y malicioso en redes IoT utilizando el conjunto de datos [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset). "
    "Este dataset, generado en un entorno virtual con el programa IXIA, simula escenarios realistas de ciberseguridad en sistemas IoT."
)

# Tabs principales
tab1, tab2, tab3 = st.tabs([
    "Visión General del Tráfico de Red",
    "Composición del Tráfico Malicioso",
    "Análisis de Rendimiento y Efectos del Ataque"
])


with tab1:
    st.header("Visión General del Tráfico de Red")
    st.write("El objetivo de este panel es ofrecer una panorámica rápida del volumen, distribución y tipo de tráfico total observado.")
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
    
    src_chart, dst_chart = chart6(security_palette)
    col7, col8 = st.columns(2)
    with col7:
        st.altair_chart(src_chart, use_container_width=True)
    with col8:
        st.altair_chart(dst_chart, use_container_width=True)

with tab2:
    st.header("Composición del Tráfico Malicioso")
    st.write(
        "Se presentan gráficos de tarta que muestran cómo se compone el tráfico malicioso por cada tipo de ataque. "
        "Permite comprender la composición y las características particulares de cada tipo de ataque."
    )

    st.markdown(
        """
    **Las variables analizadas son:**

    - **proto**: protocolo de red (e.g., TCP, UDP)
    - **service**: servicio de red utilizado (e.g., HTTP, FTP, SSH)
    - **state**: estado de la conexión
    - **sport**: puerto de origen
    - **dsport**: puerto de destino
    - **is_ftp_login**: indica si hubo autenticación FTP
    - **is_sm_ips_ports**: indica si la IP y puertos origen/destino son iguales
        """
    )

    attack_cat_selected = st.selectbox(
        "Selecciona el tipo de ataque:",
        options=['Exploits', 'Fuzzers', 'DoS', 'Reconnaissance', 'Analysis', 'Backdoor', 'Shellcode', 'Worms']
    )
    pie1, pie2 = chart14(malicious_data, security_palette, attack_cat=attack_cat_selected)
    st.altair_chart(pie1, use_container_width=True)
    st.altair_chart(pie2, use_container_width=True)



with tab3:
    st.header("Análisis de Rendimiento y Efectos del Ataque")
    st.write("Próximamente: métricas de rendimiento y efectos de los ataques en la red.")

    st.altair_chart(chart7(malicious_data, security_palette), use_container_width=True)
    st.altair_chart(chart10(malicious_data, security_palette), use_container_width=True)
    st.altair_chart(chart11(malicious_data, security_palette), use_container_width=True)

    st.altair_chart(chart15(full_data, security_palette), use_container_width=True)
    st.altair_chart(chart16(full_data, security_palette), use_container_width=True)

