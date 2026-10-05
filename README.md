# 🛡️ FIM-IPS: File Integrity Monitoring & Intrusion Prevention System

**Sistema automatizado de monitoreo de integridad de archivos con respuesta activa (Cuarentena).** Desarrollado para entornos Linux, este proyecto detecta inyecciones de código y escaladas de privilegios mediante vigilancia en tiempo real de zonas críticas del sistema.

**Autores:** Gerónimo Guevara Mansuino y Francisco Lorenzo (Grupo: "DROP TABLE GF") — Proyecto de Tesis 2026

---

## 🚀 Arquitectura del Sistema

El ecosistema de seguridad está compuesto por 5 pilares fundamentales que operan en conjunto:

1. **Capa de Detección e IPS (Python):** Utiliza la API `inotify` del kernel de Linux (a través de la biblioteca `watchdog`) para monitorear en tiempo real **tres zonas críticas del sistema**: `/etc` (configuración del SO), `/root` (directorio personal del administrador) y `/usr/bin` (binarios del sistema). Implementa un **motor de contención diferida (debounce)** que evita la cuarentena prematura durante ráfagas de eventos, permitiendo que eventos casi simultáneos (ej. CREATED + MODIFIED disparados por el mismo `tee`) compartan una ventana de lectura común para capturar el diff forense.

2. **Bóveda Forense (PostgreSQL):** Base de datos relacional encargada de almacenar evidencias inalterables (Hashes criptográficos SHA-256 y MD5, Metadatos del sistema —propietario traducido mediante `pwd` y permisos en formato octal—, y diferencias de texto), optimizada con índices para consultas de polling (eventos pendientes de notificación) y filtros analíticos de Grafana (rango de fechas, agrupación por tipo de evento).

3. **Persistencia de Servicio (Linux systemd):** Garantiza que el motor Python se ejecute ininterrumpidamente como un demonio nativo de fondo dentro de un entorno virtual (`venv`) aislado, sobreviviendo a reinicios del servidor mediante la configuración `/etc/systemd/system/fim-monitor.service` con reinicio automático ante fallos.

4. **Orquestación SOAR (n8n):** Flujo de trabajo automatizado (`FIM(Linux Ubuntu)`) que consulta cada minuto los eventos pendientes en la base de datos, los procesa **uno por uno de forma secuencial** mediante un patrón de `Split in Batches` con espaciado de 2 segundos entre envíos para evitar el error `429` de Telegram (rate limiting), y marca cada evento como notificado tras el envío exitoso.

5. **SOC Visual (Grafana):** Tableros analíticos (Dashboards) que permiten a los analistas de seguridad visualizar la línea de tiempo de los ataques, la tasa de incidentes por tipo de evento, y la salud operacional del sistema mediante gráficos agrupados por minuto y filtrados por rango de fechas.

---

## ⚙️ Características Técnicas Principales

- **Arranque en Frío (Generación de Baseline):** Al iniciar el servicio, el sistema realiza un escaneo recursivo de "Estado Cero" mapeando cada archivo en los directorios vigilados para registrar todos los hashes, metadatos y contenidos iniciales. Los eventos de BASELINE se excluyen del flujo de alerta para evitar spam, pero quedan registrados en la base de datos forense para comparativas futuras.

- **Criptografía Paralela:** Cálculo simultáneo de los algoritmos `SHA-256` y `MD5` mediante la lectura del archivo en fragmentos (chunks) de 8 KiB de memoria, garantizando la trazabilidad forense sin penalizar el rendimiento. Ambos hashes se almacenan en la base de datos para admitir verificaciones de tipo NIST o compatibilidad con herramientas externas.

- **Metadatos Forenses a Bajo Nivel:** Extracción dinámica del propietario real del archivo (traducción de UID mediante `pwd.getpwuid()`, con fallback a UID numérico si el usuario fue eliminado) y de la máscara de permisos octales (ej. `755` o `644`) utilizando `stat.S_IMODE()`. Ambos se almacenan en la base de datos para detectar escaladas de privilegios (`chmod 777`) o cambios de propiedad no autorizados (`chown`).

- **Memoria Diferencial (Extracción de Diffs):** Almacenamiento en RAM del texto original de los archivos durante el BASELINE y eventos CREADO, permitiendo capturar mediante `difflib.unified_diff()` la inyección exacta de código malicioso durante un MODIFICADO. Se descartan archivos binarios (por extensión o byte nulo), archivos mayores a 512 KiB, y se aplica utf-8 tolerante para evitar fallos por encoding.

- **Módulo IPS de Milisegundos:** Aislamiento reactivo de archivos comprometidos, moviéndolos a un directorio aislado (`/cuarentena`) con un sufijo timestamp e `.infectado`, neutralizando la amenaza en menos de 500ms. Implementa **cortacircuitos por tasa** (`UMBRAL_CUARENTENAS = 200` eventos en `VENTANA_SEGUNDOS = 30`) para evitar daño colateral durante actualizaciones legítimas de paquetes (ej. `apt upgrade`).

- **Protección contra Enlaces Simbólicos:** Los manejadores de creación, modificación y movimiento descartan explícitamente los `symlinks` (`os.path.islink()`) antes de leer o difundir su contenido, evitando que un atacante desvíe la vigilancia mediante enlaces apuntando fuera de zonas vigiladas. Caso también documentado en el Capítulo 5 de la tesis.

- **Notificación con Control de Ritmo (Rate Limiting):** El envío de alertas a Telegram está serializado mediante el nodo `Loop Over Items` (Split in Batches, 1 ítem por ciclo) del workflow n8n, con pausa de 2 segundos entre envíos, evitando el error `429 Too Many Requests` de Telegram y permitiendo que el SOC asimile los eventos en tiempo real sin perder mensajes.

- **Gestión Segura de Credenciales:** Las credenciales de la base de datos se manejan mediante variables de entorno (`python-dotenv`), evitando exponer contraseñas en el código fuente o en el repositorio. El acceso a GitHub utiliza SSH con clave `ed25519`, y las credenciales de Telegram y PostgreSQL en n8n se gestionan como _credentials_ internas (no quedan expuestas en el JSON exportado del workflow).

- **Detección de Cambios de Metadatos:** El sistema registra cambios en los permisos de archivo (ej. `chmod 777`) y cambios de propiedad (ej. `chown usuario_atacante`) como eventos `MODIFICADO`, capturando estas técnicas de escalada de privilegios incluso cuando el contenido del archivo permanece inalterado.

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

Creación de la tabla de registros, sus índices de optimización y sincronización horaria forense:

```sql
CREATE TABLE registros_archivos (
    id SERIAL PRIMARY KEY,
    nombre_archivo TEXT NOT NULL,
    ruta_completa TEXT NOT NULL,
    hash_sha256 VARCHAR (64),
    hash_md5 TEXT,
    propietario TEXT,
    permisos TEXT,
    evento TEXT NOT NULL
        CHECK (
            evento IN (
                'CREADO',
                'MODIFICADO',
                'ELIMINADO',
                'MOVIDO',
                'BASELINE',
                'EXCLUIDO_POR_POLITICA',
                'CIRCUITO_ABIERTO'
            )
        ),
    fecha_registro TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    notificado BOOLEAN DEFAULT FALSE,
    detalles_diff TEXT
);

REVOKE ALL ON registros_archivos FROM PUBLIC; 
GRANT SELECT, INSERT, UPDATE ON registros_archivos TO fim_user;
GRANT USAGE, SELECT ON SEQUENCE registros_archivos_id_seq TO fim_user; 

-- Índices para optimización de consultas en Grafana (fecha y tipo de evento)
-- y en n8n (polling de eventos pendientes de notificación)
CREATE INDEX idx_fecha_registro ON registros_archivos(fecha_registro);
CREATE INDEX idx_evento ON registros_archivos(evento);
CREATE INDEX idx_notificado_false ON registros_archivos(notificado) WHERE notificado = FALSE;

-- Sincronización de la zona horaria para garantizar la precisión forense de la región
ALTER DATABASE fim_db SET timezone TO 'America/Argentina/Buenos_Aires';
```

> **Nota sobre los índices:** `idx_fecha_registro` e `idx_evento` son consumidos por los paneles del dashboard de Grafana (filtros por rango de tiempo y agrupación por tipo de evento). `idx_notificado_false` es utilizado por el nodo `Execute a SQL query` de n8n (WHERE notificado = false), permitiendo al `Schedule Trigger` encontrar eventos pendientes en sub-milisegundos incluso con millones de registros históricos.

### 5. Persistencia del Servicio (systemd)

Para que el script opere ininterrumpidamente, se crea el archivo de configuración en `/etc/systemd/system/fim-monitor.service`. El servicio corre como `root` (necesario para tener acceso de lectura completo a `/etc`, `/root` y `/usr/bin`):

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

El workflow `FIM(Linux Ubuntu)` implementa el ciclo de notificación SOAR mediante un patrón de **loop secuencial con control de ritmo**, que procesa los eventos pendientes de a uno para evitar tanto rate limiting de Telegram como la pérdida de mensajes.

### Flujo de Ejecución

```
Schedule Trigger (cada 1 minuto)
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
Loop Over Items (Split in Batches, 1 ítem por ciclo)
        │
        ├── salida "done" ──► (fin del lote, no hay más eventos pendientes)
        │
        └── salida "loop" ──► Send a text message (Telegram, retryOnFail)
                                 Mensaje con variable: {{$json.nombre_archivo}}
                                 y detalles: {{$json.detalles_diff}}
                                    │
                                    ▼
                              Execute a SQL query1
                                UPDATE registros_archivos SET notificado = TRUE
                                WHERE id = {{ $('Loop Over Items').item.json.id }};
                                    │
                                    ▼
                              Wait (2 segundos)
                                    │
                                    └──► vuelve a la entrada de "Loop Over Items"
```

### Ciclo de Vida de la Columna `notificado`

1. El script Python (`monitor.py`) inserta cada evento con `notificado = false` (valor por defecto de la tabla).
2. Cada 1 minuto, n8n ejecuta el `Schedule Trigger` y consulta los eventos pendientes (excluyendo el ruido del `BASELINE` mediante `evento != 'BASELINE'`).
3. El nodo `If` valida que el campo `nombre_archivo` no esté vacío (evita procesar registros dañados).
4. `Loop Over Items` toma los eventos **de a uno** (Split in Batches con batch size de 1), en lugar de despacharlos todos en simultáneo.
5. Por cada ítem individual:
   - Se envía el mensaje de Telegram mediante el nodo `Send a text message` (con reintentos automáticos si falla la conexión de red).
   - Se ejecuta el UPDATE para marcar ese registro puntual como `notificado = true` (WHERE id = [id específico del ítem]).
   - Se espera 2 segundos en el nodo `Wait` para respetar los límites de tasa de Telegram.
   - El control retorna al `Loop Over Items` para procesar el siguiente ítem (si lo hay).
6. Cuando se agotan los ítems, la salida "done" del `Loop Over Items` termina el workflow, quedando listos los siguientes eventos para el próximo ciclo del `Schedule Trigger` (1 minuto después).

### Configuración del Nodo Telegram

El nodo **Send a text message** utiliza las siguientes variables extraídas de cada evento:

```
Parámetro: "text"
Valor: "=Se detectó un cambio en el archivo: {{$json.nombre_archivo}}
- Evento: {{$json.evento}}.
- Diff: {{$json.detalles_diff}}."
```

**Explicación de variables:**
- `{{$json.nombre_archivo}}`: Nombre del archivo (ej: `passwd`)
- `{{$json.evento}}`: Tipo de evento (ej: `CREADO`, `MODIFICADO`, `ELIMINADO`, `MOVIDO`)
- `{{$json.detalles_diff}}`: Contenido del diff (para eventos MODIFICADO) o descripción del evento

El prefijo `=` en el mensaje activa el **modo Markdown** de Telegram, permitiendo formateo enriquecido (negritas, monoespaciado) si se deseara en futuras iteraciones.

### ✅ Hallazgos Corregidos: Condición de Carrera en el `UPDATE` Final

**Problema original:** la query del nodo `Execute a SQL query1` era `UPDATE registros_archivos SET notificado = TRUE WHERE notificado = FALSE`, que marcaba como notificadas **todas** las filas pendientes en un solo UPDATE, incluso aquellas que no habían sido enviadas aún a Telegram. Esto generaba eventos fantasma donde se mostraba "notificado" pero nunca llegó el mensaje.

**Primera corrección (parcialmente insuficiente):** acotar el `UPDATE` al ítem puntual con `WHERE id = {{ $('Execute a SQL query').item.json.id }}`. Esto resolvía el evento fantasma para el caso de un único evento, pero cuando se acumulaban varios eventos pendientes, todos ellos eran seleccionados juntos en el primer `Execute a SQL query`, y el campo `.item.json.id` siempre hacía referencia al primero de la lista (índice 0), dejando los demás marcados sin procesar realmente.

**Corrección definitiva:** se introdujo el nodo `Loop Over Items` (Split in Batches con batch size = 1) para forzar el procesamiento secuencial, uno por ítem, antes de cada UPDATE. Esto garantiza que:
- Cada iteración toma un solo evento de la consulta original.
- Se envía a Telegram.
- Se marca como notificado **ese único ítem**.
- Se pausa 2 segundos.
- Se itera al siguiente.

**Detalle técnico relevante (crítico para la defensa):** la expresión `$json.id` no puede usarse en el `UPDATE` sin el prefijo `Loop Over Items` porque `$json` referencia el _input inmediato_ del nodo — en este caso, la salida del nodo anterior (ya sea `If` o `Execute a SQL query`). Cuando `If` o `Execute a SQL query` devuelven un array de múltiples eventos, `$json.id` siempre hace referencia a la **estructura del array completo**, no a cada ítem. Al intercalar el `Loop Over Items` **antes** del UPDATE, se garantiza que cada iteración del loop expone un único ítem como `$json`, permitiendo que `{{ $('Loop Over Items').item.json.id }}` acceda correctamente al ID del evento siendo procesado en esa vuelta específica.

**Validado mediante:** ejecución funcional de punta a punta con múltiples eventos acumulados en un mismo ciclo (4-5 modificaciones de archivo espaciadas por segundos, disparadas antes de que corra el `Schedule Trigger`). En la auditoría de n8n se verifica que cada ítem genera un nodo de ejecución separado, con UPDATE individual y delay. En la base de datos se valida con `SELECT * FROM registros_archivos WHERE notificado = false ORDER BY fecha_registro DESC LIMIT 10;` confirmando 0 filas pendientes tras el ciclo.

### Latencia de Notificación vs. Latencia de Mitigación

El `Schedule Trigger` corre cada 1 minuto, por lo que el aviso al administrador puede demorar **hasta 60 segundos** desde el incidente, a lo que se suma el espaciado del `Wait` de 2 segundos cuando hay varios eventos encadenados. Sin embargo, la **mitigación del IPS es inmediata** (< 500ms), por lo que el archivo comprometido es cuarentenado y neutralizado antes de cualquier intento de explotación, independientemente de si el administrador recibió la alerta. Esto es un trade-off intencional: el control de ritmo de Telegram no afecta la reacción de seguridad, solo la visibilidad del SOC.

---

## 🧪 Batería de Pruebas (Simulación de Ataques y Mitigación)

Para comprobar la efectividad de la arquitectura (Detección → Prevención → Alerta → Registro), se pueden ejecutar los siguientes escenarios de ataque en la terminal:

### Escenario 1: Inyección de Malware (Mitigación IPS)

Simula a un atacante creando un archivo malicioso en un directorio crítico.

```bash
echo "Payload malicioso ejecutandose..." | sudo tee /etc/ataque_final.txt
```

- **Resultado Físico:** El archivo es interceptado por el motor Python, erradicado de `/etc` y confinado en `/cuarentena` con el sufijo `.infectado` en menos de 500ms.
- **Evidencia Forense:** PostgreSQL registra dos eventos en rápida sucesión: `CREADO` (durante el on_created inicial) y `MODIFICADO` (si inotify emite eventos para la escritura buffered del `tee`), capturando el diff exacto del texto inyectado mediante la comparación entre el BASELINE y el contenido actual.

### Escenario 2: Escalada de Privilegios (Cambio de Permisos)

Simula a un atacante otorgando permisos máximos de ejecución a un archivo para correr un script.

```bash
sudo chmod 777 /etc/prueba_metadatos.txt
```

- **Evidencia Forense:** El motor detecta la alteración de metadatos (aunque el contenido del archivo no haya cambiado) y registra el evento `MODIFICADO` en la base de datos con el estado crítico `777` en la columna `permisos`. El diff estará vacío o mostrará "evento MODIFICADO redundante" porque el contenido es idéntico, pero el registro de permisos capturará la escalada.

### Escenario 3: Secuestro de Propiedad (Chown)

Simula a un atacante cambiando el dueño del archivo para ocultar sus rastros o evadir restricciones de control de acceso.

```bash
sudo chown usuario_atacante:usuario_atacante /etc/prueba_metadatos.txt
```

- **Evidencia Forense:** La biblioteca `pwd` del script traduce el cambio a bajo nivel y registra en la base de datos el nuevo propietario (`usuario_atacante`) en la columna `propietario`. El campo de diff indicará cambio de metadatos aunque el contenido sea idéntico.

### Escenario 4: Movimiento/Renombrado hacia zona vigilada

Simula a un atacante reemplazando un binario legítimo mediante un `mv` (técnica común para evadir detección de escritura directa).

```bash
echo "contenido" | sudo tee /etc/zona_a/archivo_prueba
sudo mv /etc/zona_a/archivo_prueba /etc/zona_b/archivo_renombrado
```

- **Evidencia Forense:** El motor captura el evento `MOVIDO`, recalcula los hashes del archivo en su nueva ubicación y registra la ruta de origen en el campo `detalles_diff` (ej: "Movido desde: /etc/zona_a/archivo_prueba").
- **Nota técnica:** `inotify` solo emite un evento `MOVED` verdadero (con cookie emparejado) cuando tanto el origen como el destino están dentro de directorios con _watch_ activo en el mismo punto de montaje. Movimientos desde `/tmp` a `/etc` se registran como `ELIMINADO` en `/tmp` y `CREADO` en `/etc` de forma separada, lo cual es correcto desde una perspectiva de vigilancia de zonas (la zona `/etc` recibió un archivo nuevo, aunque provenga de fuera).

### Escenario 5: Prueba de Punta a Punta (Detección → Mitigación → Alerta)

Para validar el flujo completo de la arquitectura, incluyendo la notificación SOAR:

```bash
echo "Payload de prueba end-to-end" | sudo tee /etc/prueba_e2e.txt
```

- **Resultado esperado en < 500ms:** el archivo es cuarentenado por el IPS de forma inmediata, movido a `/cuarentena/prueba_e2e.txt_YYYYMMDD-HHMMSS.infectado`.
- **Resultado esperado en hasta 60 segundos:** llega un mensaje de Telegram avisando del evento, y la fila correspondiente en `registros_archivos` pasa de `notificado = false` a `notificado = true`.
- **Verificación en base de datos**, justo después de generar el evento (antes de que corra el `Schedule Trigger`):

```sql
SELECT id, evento, notificado, nombre_archivo, detalles_diff 
FROM registros_archivos 
WHERE nombre_archivo = 'prueba_e2e.txt'
ORDER BY id DESC LIMIT 3;
```

- **Verificación post-notificación** (confirmar que la fila fue procesada):

```sql
SELECT COUNT(*) FROM registros_archivos 
WHERE notificado = false AND evento != 'BASELINE';
```

Debería retornar 0 si el workflow n8n procesó todos los eventos pendientes.

### Escenario 6: Validación del Loop Secuencial con Múltiples Eventos

Para comprobar que el `Loop Over Items` procesa los eventos de a uno, en lugar de despacharlos todos en simultáneo (y así evitar el `429` de Telegram), se puede forzar la acumulación de varios eventos:

```bash
for i in 1 2 3 4; do
  echo "cambio de prueba #$i - $(date +%s)" | sudo tee -a /etc/fim_test_file.txt
  sleep 2
done
```

- **Verificación previa** (confirmar que se acumularon los pendientes):

```sql
SELECT id, nombre_archivo, evento, notificado, fecha_registro
FROM registros_archivos 
WHERE nombre_archivo = 'fim_test_file.txt' AND notificado = false
ORDER BY fecha_registro DESC LIMIT 10;
```

- **Resultado esperado:** entre 4 y 5 filas con `notificado = false` (una por cada iteración del `for`, más posiblemente un MODIFICADO inicial del baseline).

- **Ejecución del workflow n8n** (manualmente o aguardando al próximo `Schedule Trigger`):

En el historial de ejecuciones de n8n, el nodo `Loop Over Items` debe correr **una vez por ítem** (4 iteraciones separadas), con los envíos de Telegram espaciados por el intervalo del `Wait` (2 segundos), no todos en simultáneo. Esto se verifica en la pestaña "Executions" de n8n, expandiendo la rama "Loop Over Items" y confirmando que hay 4 salidas "loop" seguidas.

- **Verificación posterior** (0 filas pendientes tras el ciclo):

```sql
SELECT COUNT(*) FROM registros_archivos 
WHERE notificado = false AND evento != 'BASELINE' AND nombre_archivo = 'fim_test_file.txt';
```

Debería retornar 0 una vez que el workflow terminó su ciclo.

---

## 📊 Visualización Analítica (SOC en Grafana)

Para el Centro de Operaciones de Seguridad, se diseñó un panel de control que permite observar el tráfico de incidentes, detectar picos de actividad sospechosa y evaluar la tendencia de ataques. A continuación, se detalla la consulta SQL principal utilizada para generar el gráfico de series temporales:

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
- `WHERE ... AND evento != 'BASELINE'`: Filtro crítico de exclusión de ruido. Ignora los archivos escaneados durante el arranque del sistema (Estado Cero), permitiendo que el gráfico muestre **únicamente** eventos operacionales (CREADO, MODIFICADO, ELIMINADO, MOVIDO) y anómalos (EXCLUIDO_POR_POLITICA, CIRCUITO_ABIERTO).
- `GROUP BY 1, 2`: Agrupa por minuto y por tipo de evento, generando una serie por cada evento, permitiendo que los analistas distingan patrones (ej. un pico de MODIFICADO sugiere modificación de binarios; un pico de CREADO sugiere inyección de nuevos archivos).

**Ejemplo de lectura del dashboard:**

Si el gráfico muestra un pico de **5 eventos CREADO** en el minuto 14:32, seguido de un pico de **3 eventos MODIFICADO** en el minuto 14:33, el analista puede interpolar: entre 14:31 y 14:32 hubo una inyección de 5 archivos nuevos; entre 14:32 y 14:33, 3 de ellos fueron alterados. Esto es consistente con un ataque de **dos fases: carga + activación de payload**, típico de técnicas de obfuscación o retardo de ejecución.

---

## 🔐 Seguridad del Repositorio

- Las credenciales de base de datos nunca se versionan en texto plano; se gestionan vía `.env` (excluido del repositorio mediante `.gitignore`).
- El entorno virtual (`venv/`) tampoco se versiona, ya que es reproducible a partir de las dependencias declaradas en `pip install`.
- El acceso al repositorio de GitHub desde el servidor se realiza mediante autenticación SSH (clave `ed25519`), evitando el uso de tokens o contraseñas en texto plano.
- Las credenciales de Telegram y PostgreSQL usadas por n8n se gestionan como _credentials_ internas de la instancia (no quedan expuestas en el JSON exportado del workflow, aunque el JSON sí contiene referencias de los credential IDs para re-mapeo en importación).
- Los logs de `journalctl` del servicio systemd contienen información sensible de debugging; se recomienda no compartirlos públicamente sin ofuscación de rutas.

---

## 📦 Importar el Workflow de n8n

El archivo `FIM(Linux Ubuntu).json` contiene la definición completa del flujo de orquestación, incluyendo los nodos `Loop Over Items` (Split in Batches, batch size = 1) y `Wait` (2 segundos) para control de ritmo. Para importarlo en una instancia n8n propia:

1. Abrir n8n → **Workflows** → **Import from File**.
2. Seleccionar `FIM(Linux Ubuntu).json`.
3. Configurar las credenciales de **Postgres** y **Telegram** propias de tu entorno (el JSON exportado no incluye contraseñas ni tokens, solo referencias de credential IDs).
4. Reemplazar el `chatId` en el nodo `Send a text message` por el ID del chat de Telegram donde deseas recibir alertas.
5. Activar el workflow (toggle "Active") para que el `Schedule Trigger` comience a correr cada 1 minuto.

**Parámetros editables en n8n tras la importación:**

- **Schedule Trigger → rule → interval:** Ajustar la frecuencia de polling (default: 1 minuto). Si la latencia de notificación es crítica, reducir a 30 segundos; si los eventos son escasos, aumentar a 5 minutos para ahorrar recursos.
- **Wait → amount:** Tiempo de espera entre envíos de Telegram (default: 2 segundos). Telegram permite ~3 mensajes por segundo; con 2 segundos entre envíos estamos muy por debajo del límite (`429`). Reducir solo si es urgencia extrema.
- **Loop Over Items → options:** El batch size está configurado a 1 por defecto. **No modificar** — cambiar a valores mayores reabre la condición de carrera documentada.
- **Send a text message → parameters → text:** Template del mensaje. La versión actual incluye `nombre_archivo`, `evento` y `detalles_diff`. Personalizar según necesidades (ej. agregar emojis, URLs de dashboards, etc.).

---

## 📋 Archivos Principales del Proyecto

- **`monitor.py`:** Motor principal de vigilancia. Implementa inotify, baseline, metadatos forenses, diffs, cuarentena diferida, cortacircuitos y sincronización con PostgreSQL.
- **`FIM(Linux Ubuntu).json`:** Flujo n8n exportado. Importar en tu instancia para habilitar notificaciones a Telegram.
- **`.env`:** Archivo de configuración (NO versionado). Contiene credenciales de base de datos.
- **`.gitignore`:** Excluye `.env`, `venv/`, y archivos de sistema.
- **`tests/test_contencion.py`:** Suite de pruebas unitarias para funciones de decisión (vigilancia, exclusión, cortacircuitos).
- **`README.md`:** Este archivo. Documentación completa del sistema.

---

## 🎯 Próximas Mejoras (Roadmap)

- **Integración SIEM:** Envío de eventos a un SIEM centralizado (Splunk, ELK) para correlación de alertas a nivel empresarial.
- **Cifrado de tránsito:** TLS 1.3 para la comunicación Python ↔ PostgreSQL en ambientes de producción.
- **Políticas de retención:** Rotación automática de registros históricos (ej. borrar eventos de BASELINE tras 90 días) para ahorrar espacio.
- **Dashboard en tiempo real:** Websocket de n8n a Grafana para visualización de alertas sin latencia de 1 minuto.
- **Antivirus integrado:** Escaneo ClamAV de archivos cuarentenados antes de archivarlos (opcional).

---

## 📞 Contacto y Soporte

- **Gerónimo Guevara Mansuino:** gguevaraman@gmail.com
- **Francisco Lorenzo:** franciscopacolorenzo@gmail.com
- **Repositorio:** https://github.com/GuevaraMansuino/TesisCyberseguridad_FIM
- **Documentación de Tesis:** https://drive.google.com/file/d/1O6AUNSnATEwKyR5jc1LC0Bdwof_q3lF2/view

---

**Última actualización:** Septiembre 2026  
**Versión:** 2.2.2 (Workflow n8n actualizado con Loop Over Items secuencial y Wait de control de ritmo)
