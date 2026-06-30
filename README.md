# 🛡️ FIM-IPS: File Integrity Monitoring & Intrusion Prevention System

**Sistema automatizado de monitoreo de integridad de archivos con respuesta activa (Cuarentena).** Desarrollado para entornos Linux, este proyecto detecta inyecciones de código y escaladas de privilegios en milisegundos, alertando vía plataformas SOAR (n8n/Telegram) y aislando la amenaza automáticamente para reducir el Tiempo Medio de Mitigación (MTTM) a cero.

**Autores:** Gerónimo Guevara Mansuino y Francisco Lorenzo (Grupo: "DROP TABLE GF") — Proyecto de Tesis 2026

---

## 🚀 Arquitectura del Sistema

El ecosistema de seguridad está compuesto por 5 pilares fundamentales que operan en conjunto:

1. **Capa de Detección e IPS (Python):** Utiliza la API `inotify` del kernel de Linux (a través de la biblioteca `watchdog`) para monitorear en tiempo real **tres zonas críticas del sistema**: `/etc`, `/root` y `/usr/bin`. Actúa como el cerebro del sistema.
2. **Bóveda Forense (PostgreSQL):** Base de datos relacional encargada de almacenar evidencias inalterables (Hashes criptográficos, Metadatos del sistema y diferencias de texto).
3. **Persistencia de Servicio (Linux systemd):** Garantiza que el motor se ejecute como un demonio nativo de fondo dentro de un entorno virtual (`venv`) aislado, sobreviviendo a reinicios del servidor y operando con privilegios de administrador.
4. **Orquestación SOAR (n8n):** Flujo de trabajo automatizado (`FIM(Linux Ubuntu)`) que consulta cada minuto los eventos pendientes en la base de datos y despacha alertas a Telegram, marcando cada registro como notificado una vez procesado.
5. **SOC Visual (Grafana):** Tableros analíticos (Dashboards) que permiten a los analistas de seguridad visualizar la línea de tiempo de los ataques y la salud del sistema.

---

## ⚙️ Características Técnicas Principales

- **Arranque en Frío (Generación de Baseline):** Al iniciar el servicio, el sistema realiza un escaneo de "Estado Cero" mapeando recursivamente cada directorio vigilado para registrar todos los archivos legítimos antes de comenzar la vigilancia activa.
- **Criptografía Paralela:** Cálculo simultáneo de los algoritmos `SHA-256` y `MD5` mediante la lectura del archivo en fragmentos (chunks) de memoria, garantizando la trazabilidad forense sin penalizar el rendimiento del servidor.
- **Metadatos Forenses a Bajo Nivel:** Extracción dinámica del propietario real del archivo (traducción de UID) y de la máscara de permisos octales (ej. `755` o `644`) utilizando la biblioteca nativa `os.stat`.
- **Memoria Diferencial (Extracción de Diffs):** Almacenamiento en RAM del texto original de los archivos para capturar y documentar la inyección exacta de código malicioso mediante la biblioteca `difflib`.
- **Módulo IPS de Milisegundos:** Aislamiento reactivo de archivos comprometidos, moviéndolos a un directorio aislado (`/cuarentena`), neutralizando la amenaza antes de que el atacante pueda actuar. Cubre los cuatro eventos principales del ciclo de vida de un archivo: `CREADO`, `MODIFICADO`, `ELIMINADO` y `MOVIDO`.
- **Gestión Segura de Credenciales:** Las credenciales de la base de datos se manejan mediante variables de entorno (`python-dotenv`), evitando exponer contraseñas en el código fuente o en el repositorio de Git.

---

## 🛠️ Instalación y Despliegue

### 1. Clonar el repositorio y preparar el entorno virtual

```bash
git clone git@github.com:GuevaraMansuino/TesisCyberseguridad_FIM.git
cd TesisCyberseguridad_FIM

# Si falta el paquete venv del sistema
sudo apt install python3.12-venv

python3 -m venv venv
source venv/bin/activate
pip install python-dotenv psycopg2-binary watchdog
deactivate
```

### 2. Variables de entorno

Crear un archivo `.env` en la raíz del proyecto (este archivo **no** se versiona, ya está excluido vía `.gitignore`):

```
DB_HOST=localhost
DB_NAME=fim_db
DB_USER=fim_user
DB_PASS=tu_contraseña_segura
```

Restringir permisos del archivo, ya que contiene credenciales sensibles:

```bash
chmod 600 .env
```

### 3. Directorio de Cuarentena

Para que el motor IPS pueda neutralizar las amenazas, se debe crear una "celda de aislamiento":

```bash
sudo mkdir -p /cuarentena
sudo chmod 700 /cuarentena
```

### 4. Base de Datos (Bóveda Forense PostgreSQL)

Creación de la tabla de registros y sincronización horaria forense:

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

### 5. Persistencia del Servicio (systemd)

Para que el script opere ininterrumpidamente, se crea el archivo de configuración en `/etc/systemd/system/fim-monitor.service`. El servicio corre como `root` (necesario para tener acceso de lectura completo sobre `/root` y `/usr/bin`) y ejecuta el script usando el intérprete del entorno virtual del proyecto:

```ini
[Unit]
Description=FIM Monitor - Tesis Cyberseguridad
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/geron/tesisFim
ExecStart=/home/geron/tesisFim/venv/bin/python /home/geron/tesisFim/monitor.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Activación y arranque del servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable fim-monitor.service
sudo systemctl start fim-monitor.service
sudo systemctl status fim-monitor.service
```

Para monitorear los logs en tiempo real:

```bash
journalctl -u fim-monitor.service -f
```

---

## 🔔 Orquestación de Alertas (n8n → Telegram)

El workflow `FIM(Linux Ubuntu)` implementa el ciclo de notificación SOAR mediante 4 nodos encadenados:

```
Schedule Trigger (cada 1 min)
        │
        ▼
Execute a SQL query
  SELECT * FROM registros_archivos
  WHERE notificado = false AND evento != 'BASELINE'
        │
        ▼
If (nombre_archivo no está vacío)
        │
        ▼
Send a text message (Telegram)
  "Se detectó un cambio en el archivo: {{nombre_archivo}} - Evento: {{evento}})."
        │
        ▼
Execute a SQL query1
  UPDATE registros_archivos SET notificado = TRUE
  WHERE id = {{ $('Execute a SQL query').item.json.id }};
```

**Ciclo de vida de la columna `notificado`:**
1. El script Python inserta cada evento con `notificado = false` (valor por defecto de la tabla).
2. Cada 1 minuto, n8n consulta los eventos pendientes (excluyendo el ruido del `BASELINE`).
3. Por cada fila obtenida, valida que tenga nombre de archivo y dispara un mensaje de Telegram.
4. Tras notificar, ejecuta el `UPDATE` que cierra el ciclo marcando el evento como notificado.

### ✅ Hallazgo corregido: condición de carrera en el `UPDATE` final

**Problema original:** la query del nodo `Execute a SQL query1` era `UPDATE registros_archivos SET notificado = TRUE WHERE notificado = FALSE`, que marca como notificadas **todas** las filas pendientes en el momento de su ejecución, no únicamente la que efectivamente se acaba de enviar a Telegram en esa corrida. Si un nuevo evento se insertaba en la base entre el paso del `SELECT` y el paso del `UPDATE` del mismo ciclo, ese evento quedaba marcado como notificado sin haber generado una alerta real — un evento "fantasma" que el administrador nunca llega a ver.

**Corrección aplicada:**
```sql
UPDATE registros_archivos SET notificado = TRUE WHERE id = {{ $('Execute a SQL query').item.json.id }};
```

Este `UPDATE` se ejecuta una vez por cada fila procesada (n8n itera el nodo por ítem) y queda acotado al `id` puntual que originó esa notificación, eliminando la ventana de carrera.

**Detalle técnico relevante (vale la pena explicarlo en la defensa):** la primera versión del fix usaba `WHERE id = {{$json.id}}`, que falló con resultado `undefined`. La causa es que `$json` referencia el *input inmediato* del nodo — en este caso, la salida del nodo `Send a text message` (Telegram), que **sobrescribe** el `$json` con los campos de su propia respuesta de API (`message_id`, `chat`, `date`, etc.), perdiendo el campo `id` original de la tabla. La expresión `$('Execute a SQL query').item.json.id` resuelve esto apuntando explícitamente al nodo del `SELECT` original, sin depender de qué transformaciones haya sufrido el dato en los nodos intermedios.

**Validado mediante:** ejecución funcional de punta a punta (evento → cuarentena → fila en `notificado=false` → ciclo de n8n → `notificado=true` tras el envío del Telegram).

### Latencia de notificación vs. latencia de mitigación

El `Schedule Trigger` corre cada 1 minuto, por lo que el aviso al administrador puede demorar hasta 60 segundos desde el incidente. Esto es independiente del tiempo de contención del IPS (sub-segundo, vía `inotify`), que actúa sobre el archivo sin esperar a la notificación. Vale aclarar esta distinción en la defensa: el **MTTM de contención** (aislamiento del archivo) es prácticamente cero, mientras que el **MTTM de conocimiento humano** (que el administrador se entere) depende del intervalo de polling configurado en n8n.

---

## 🧪 Batería de Pruebas (Simulación de Ataques y Mitigación)

Para comprobar la efectividad de la arquitectura (Detección → Prevención → Alerta → Registro), se pueden ejecutar los siguientes escenarios de ataque en la terminal:

### Escenario 1: Inyección de Malware (Mitigación IPS)

Simula a un atacante creando un archivo malicioso en un directorio crítico.

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

### Escenario 4: Movimiento/Renombrado hacia zona vigilada

Simula a un atacante reemplazando un binario legítimo mediante un `mv` (técnica común para evadir detección de escritura directa).

```bash
echo "contenido" | sudo tee /etc/zona_a/archivo_prueba
sudo mv /etc/zona_a/archivo_prueba /etc/zona_b/archivo_renombrado
```

- **Evidencia Forense:** El motor captura el evento `MOVIDO`, calcula los hashes del archivo en su nueva ubicación y registra la ruta de origen.
- **Nota técnica:** `inotify` solo emite un evento `MOVED` verdadero (con cookie emparejado) cuando tanto el origen como el destino están dentro de directorios con *watch* activo. Movimientos desde fuera de las zonas vigiladas (ej. `/tmp`) hacia adentro son reportados por el kernel como eventos `CREATED`, y son neutralizados por ese handler antes de llegar a `on_moved` — una capa adicional de cobertura, no una falla.

### Escenario 5: Prueba de punta a punta (Detección → Mitigación → Alerta)

Para validar el flujo completo de la arquitectura, incluyendo la notificación SOAR:

```bash
echo "Payload de prueba end-to-end" | sudo tee /etc/prueba_e2e.txt
```

- **Resultado esperado en segundos:** el archivo es cuarentenado por el IPS de forma inmediata.
- **Resultado esperado en hasta 1 minuto:** llega un mensaje de Telegram avisando del evento, y la fila correspondiente en `registros_archivos` pasa de `notificado = false` a `notificado = true`.
- **Verificación en base de datos**, justo después de generar el evento (antes de que corra el `Schedule Trigger`):
```sql
SELECT id, evento, notificado FROM registros_archivos ORDER BY id DESC LIMIT 3;
```

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
- `WHERE ... AND evento != 'BASELINE'`: Filtro crítico de exclusión de ruido. Ignora los archivos escaneados durante el arranque del sistema (Estado Cero), permitiendo que el gráfico muestre **únicamente** los incidentes reales (Inyecciones, Modificaciones, Eliminaciones o Movimientos).

---

## 🔐 Seguridad del Repositorio

- Las credenciales de base de datos nunca se versionan en texto plano; se gestionan vía `.env` (excluido del repositorio mediante `.gitignore`).
- El entorno virtual (`venv/`) tampoco se versiona, ya que es reproducible a partir de las dependencias declaradas.
- El acceso al repositorio de GitHub desde el servidor se realiza mediante autenticación SSH (clave `ed25519`), evitando el uso de tokens o contraseñas en texto plano.
- Las credenciales de Telegram y PostgreSQL usadas por n8n se gestionan como *credentials* internas de la instancia (no quedan expuestas en el JSON exportado del workflow).

---

## 📦 Importar el Workflow de n8n

El archivo `FIM(Linux Ubuntu).json` contiene la definición completa del flujo de orquestación. Para importarlo en una instancia de n8n:

1. Abrir n8n → **Workflows** → **Import from File**.
2. Seleccionar `FIM(Linux Ubuntu).json`.
3. Configurar las credenciales de **Postgres** y **Telegram** propias de tu entorno (el JSON exportado no incluye contraseñas ni tokens).
4. Activar el workflow (toggle "Active") para que el `Schedule Trigger` comience a correr cada 1 minuto.

> 💡 Mejora cosmética pendiente: corregir el texto del nodo *Send a text message*, que tiene un paréntesis de cierre sobrante (`...Evento: {{$json.evento}}).` debería ser `...Evento: {{$json.evento}}.`).
