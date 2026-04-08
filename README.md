# 🛡️ FIM-IPS: File Integrity Monitoring & Intrusion Prevention System

**Sistema automatizado de monitoreo de integridad de archivos con respuesta activa (Cuarentena).** Desarrollado para entornos Linux, este proyecto detecta inyecciones de código y escaladas de privilegios en milisegundos, alertando vía plataformas SOAR (n8n/Telegram) y aislando la amenaza automáticamente para reducir el Tiempo Medio de Mitigación (MTTM) a cero.

**Autor:** Gerónimo Guevara Mansuino (Proyecto de Tesis - 2026)

---

## 🚀 Arquitectura del Sistema

El ecosistema de seguridad está compuesto por 5 pilares fundamentales que operan en conjunto:

1. **Capa de Detección e IPS (Python):** Utiliza la API `inotify` del kernel de Linux (a través de la biblioteca `watchdog`) para monitorear el directorio crítico `/etc` en tiempo real. Actúa como el cerebro del sistema.
2. **Bóveda Forense (PostgreSQL):** Base de datos relacional encargada de almacenar evidencias inalterables (Hashes criptográficos, Metadatos del sistema y diferencias de texto).
3. **Persistencia de Servicio (Linux systemd):** Garantiza que el motor se ejecute como un demonio nativo de fondo, sobreviviendo a reinicios del servidor y operando con privilegios de administrador.
4. **Orquestación SOAR (n8n):** Flujo de trabajo automatizado que filtra eventos de la base de datos y despacha alertas instantáneas a dispositivos móviles (Telegram).
5. **SOC Visual (Grafana):** Tableros analíticos (Dashboards) que permiten a los analistas de seguridad visualizar la línea de tiempo de los ataques y la salud del sistema.

---

## ⚙️ Características Técnicas Principales

- **Arranque en Frío (Generación de Baseline):** Al iniciar el servicio, el sistema realiza un escaneo de "Estado Cero" mapeando recursivamente el directorio para registrar todos los archivos legítimos antes de comenzar la vigilancia activa.
- **Criptografía Paralela:** Cálculo simultáneo de los algoritmos `SHA-256` y `MD5` mediante la lectura del archivo en fragmentos (chunks) de memoria, garantizando la trazabilidad forense sin penalizar el rendimiento del servidor.
- **Metadatos Forenses a Bajo Nivel:** Extracción dinámica del propietario real del archivo (traducción de UID) y de la máscara de permisos octales (ej. `755` o `644`) utilizando la biblioteca nativa `os.stat`.
- **Memoria Diferencial (Extracción de Diffs):** Almacenamiento en RAM del texto original de los archivos para capturar y documentar la inyección exacta de código malicioso mediante la biblioteca `difflib`.
- **Módulo IPS de Milisegundos:** Aislamiento reactivo de archivos comprometidos, moviéndolos a un directorio aislado (`/cuarentena`) sin permisos de ejecución, neutralizando la amenaza antes de que el atacante pueda actuar.

---

## 🛠️ Instalación y Despliegue

### 1. Preparación del Entorno (Directorio de Cuarentena)

Para que el motor IPS pueda neutralizar las amenazas, se debe crear una "celda de aislamiento". Se le otorgan permisos nulos (`000`) para garantizar que ningún binario o script malicioso pueda ser ejecutado ni leído desde allí.

```bash
sudo mkdir /cuarentena
sudo chmod 000 /cuarentena
```

### 2. Base de Datos (Bóveda Forense PostgreSQL)

Creación de la tabla de registros y sincronización horaria forense. Se incluyen las columnas necesarias para almacenar la evidencia extendida de la Fase 3 del proyecto.

```sql
CREATE TABLE registros_archivos (
    id SERIAL PRIMARY KEY,
    nombre_archivo TEXT NOT NULL,
    ruta_completa TEXT NOT NULL,
    hash_sha256 TEXT,
    hash_md5 TEXT,
    propietario TEXT,
    permisos TEXT,
    evento TEXT NOT NULL,
    fecha_registro TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    notificado BOOLEAN DEFAULT FALSE,
    detalles_diff TEXT
);

-- Sincronización de la zona horaria para garantizar la precisión forense de la región
ALTER DATABASE fim_db SET timezone TO 'America/Argentina/Buenos_Aires';
```

### 3. Persistencia del Servicio (systemd)

Para que el script opere ininterrumpidamente, se crea el archivo de configuración en la ruta `/etc/systemd/system/fim_monitor.service`. Esta configuración indica que el servicio debe arrancar después de la red y la base de datos, y reiniciarse automáticamente en caso de fallo (`Restart=on-failure`).

```ini
[Unit]
Description=Motor FIM e IPS - Monitoreo de Integridad de Archivos
After=network.target postgresql.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /ruta/absoluta/a/tu/script/monitor.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Activación y arranque del servicio en el kernel de Linux:

```bash
sudo systemctl enable fim_monitor
sudo systemctl start fim_monitor
```

---

## 🧪 Batería de Pruebas (Simulación de Ataques y Mitigación)

Para comprobar la efectividad de la arquitectura (Detección -> Prevención -> Alerta -> Registro), se pueden ejecutar los siguientes escenarios de ataque en la terminal:

### Escenario 1: Inyección de Malware (Mitigación IPS)

Simula a un atacante creando un archivo malicioso en el directorio crítico.

```bash
echo "Payload malicioso ejecutandose..." | sudo tee /etc/ataque_final.txt
```

- **Resultado Físico:** El archivo es interceptado por el motor Python, erradicado de `/etc` y confinado en `/cuarentena` con el sufijo `.infectado` en menos de 500ms.
- **Evidencia Forense:** PostgreSQL registra el evento `CREADO` y `MODIFICADO`, capturando el Diff exacto del texto inyectado.

### Escenario 2: Escalada de Privilegios

Simula a un atacante otorgando permisos máximos de ejecución a un archivo para correr un script.

```bash
sudo chmod 777 /etc/prueba_metadatos.txt
```

- **Evidencia Forense:** El motor detecta la alteración de metadatos y la base de datos registra el estado crítico `777` en la columna de permisos.

### Escenario 3: Secuestro de Propiedad (Chown)

Simula a un atacante cambiando el dueño del archivo para ocultar sus rastros o evadir restricciones.

```bash
sudo chown usuario_atacante:usuario_atacante /etc/prueba_metadatos.txt
```

- **Evidencia Forense:** La biblioteca `pwd` del script traduce el cambio a bajo nivel y registra en la base de datos al nuevo propietario no autorizado.

---

## 📊 Visualización Analítica (SOC en Grafana)

Para el Centro de Operaciones de Seguridad, se diseñó un panel de control que permite observar el tráfico de incidentes. A continuación, se detalla la consulta SQL principal utilizada para generar la **Línea de Tiempo de Eventos Críticos**.

```sql
SELECT
  $__timeGroupAlias(fecha_registro,'1m'),
  evento AS metric,
  count(evento) AS value
FROM registros_archivos
WHERE $__timeFilter(fecha_registro) AND evento != 'BASELINE'
GROUP BY 1, 2
ORDER BY 1;
```

**Análisis de la consulta:**

- `$__timeGroupAlias(..., '1m')`: Macro de Grafana que agrupa los ataques en bloques de 1 minuto, permitiendo visualizar "picos" de actividad sospechosa en el gráfico de barras.
- `WHERE ... AND evento != 'BASELINE'`: Filtro crítico de exclusión de ruido. Ignora los cientos de archivos escaneados durante el arranque del sistema (Estado Cero), permitiendo que el gráfico muestre **únicamente** los incidentes reales (Inyecciones, Modificaciones o Eliminaciones).
