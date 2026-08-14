import time
import hashlib
import psycopg2
import difflib
import os
import shutil
import pwd # Sirve para traducir el ID de usuario al nombre (ej: root)
import stat # Sirver para leer los permisos (ej: chmod 755)
from collections import deque
from threading import Lock
from dotenv import load_dotenv

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

#--- CONFIGURACION ---
load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
PATHS_TO_WATCH = ["/etc", "/root", "/usr/bin"]

# Rutas excluidas de la cuarentena automática: forman parte del
# funcionamiento normal del sistema operativo y del gestor de
# paquetes, y NO deben retirarse aunque estén dentro de una zona
# vigilada.
RUTAS_EXCLUIDAS = {
    "/etc/resolv.conf",
    "/etc/mtab",
    "/etc/ld.so.cache",
    "/etc/apt/",
    "/etc/dpkg/",
    "/var/lib/dpkg/",
    "/var/lib/apt/",
}

# Cortacircuitos por tasa: si se superan UMBRAL_CUARENTENAS eventos
# de contención en VENTANA_SEGUNDOS, el sistema suspende la cuarentena
# automática (pasa a modo "solo alerta") para no destruirse a sí
# mismo ante una actualización legítima masiva (ej. apt upgrade).
UMBRAL_CUARENTENAS = 10
VENTANA_SEGUNDOS = 30
_historial_cuarentenas = deque()
_lock_circuito = Lock()

#--- MEMORIA RAM PARA EL DIFF ---
memoria_archivos = {}

EXTENSIONES_BINARIAS = {'.so', '.bin', '.o', '.a', '.pyc', '.jpg', '.png', '.gz', '.zip'}
LIMITE_BYTES_DIFF = 512 * 1024  # 512 KiB

def leer_archivo_texto(ruta):
   try:
      ext = os.path.splitext(ruta)[1].lower()
      if ext in EXTENSIONES_BINARIAS:
         return []
      if os.path.getsize(ruta) > LIMITE_BYTES_DIFF:
         return []
      with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
          return f.readlines()
   except Exception:
      return []

#--- FUNCIONES AUXILIARES ---
def get_hashes(filepath):
    try:
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)
            return sha256_hash.hexdigest(), md5_hash.hexdigest()
    except FileNotFoundError:
        return None, None
    except Exception as e:
        print(f"Error leyendo {filepath}: {e}")
        return None, None

def obtener_metadatos(filepath):
    try:
        info = os.stat(filepath)
        # 1. Obtener el nombre del propietario (ej: 'root' o 'geron')
        try:
            propietario = pwd.getpwuid(info.st_uid).pw_name
        except KeyError:
            propietario = str(info.st_uid) # Por si el usuario fue borrado

        # 2. Obtener los permisos en formato octal clasico (ej: '0o755' -> '755')
        permisos = oct(stat.S_IMODE(info.st_mode))[-3:]

        return propietario, permisos
    except Exception as e:
        return "desconocido", "desconocido"

def log_to_db(nombre_archivo, ruta_completa, hash_sha256, hash_md5, evento, detalles_diff="", propietario="desconocido", permisos="desconocido"):
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        cursor = conn.cursor()
        query = "INSERT INTO registros_archivos (nombre_archivo, ruta_completa, hash_sha256, hash_md5, evento, detalles_diff, propietario, permisos) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(query, (nombre_archivo, ruta_completa, hash_sha256, hash_md5, evento, detalles_diff, propietario, permisos))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error en BD: {e}", flush=True)

#--- FASE 2: GENERACIÓN DE BASELINE INICIAL ---

def obtener_rutas_baseline():
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        cursor = conn.cursor()
        # Buscamos que archivos ya tienen su BASELINE
        cursor.execute("SELECT ruta_completa FROM registros_archivos WHERE evento = 'BASELINE'")
        rutas = {row[0] for row in cursor.fetchall()}
        # Guardamos los resultados en un SET (conjunto) para busqueda super rapidas
        cursor.close()
        conn.close()
        return rutas
    except Exception as e:
        print(f"Error consultado Baselines previas: {e}", flush=True)
        return set()


def generar_baseline():
    print(f"Iniciando escaneo de Baseline multiple... {PATHS_TO_WATCH}...", flush=True)
    rutas_existentes = obtener_rutas_baseline()
    contador_archivos = 0
    for path in PATHS_TO_WATCH:
        if not os.path.exists(path):
            print(f"ADVERTENCIA: La ruta {path} no existe.", flush=True)
            continue

        print(f"--> Analizando zona critica: {path}", flush=True)
    # os.walk recorre la carpeta principal y todas las subcarpetas por dentro
        for root, dirs, files in os.walk(path):
            for file in files:
                ruta_completa = os.path.join(root, file)

                # Verificamos que sea un archivo real y no un acceso directo (symlink)
                if os.path.isfile(ruta_completa) and not os.path.islink(ruta_completa):
                    try:
                        h_sha256, h_md5 = get_hashes(ruta_completa)
                        propietario, permisos = obtener_metadatos(ruta_completa)
                        if h_sha256:
                            # 1. Guardamos el texto en la memoria RAM para futuros Diffs
                            memoria_archivos[ruta_completa] = leer_archivo_texto(ruta_completa)

                            if ruta_completa not in rutas_existentes:

                                # 2. Guardamos en PostgreSQL con el evento "BASELINE"
                                log_to_db(file, ruta_completa, h_sha256, h_md5, 'BASELINE', 'Generación de estado seguro inicial', propietario, permisos)
                                contador_archivos += 1
                    except Exception:
                        # Si no tenemos permisos para leer un archivo específico, lo saltamos
                        pass

        print(f"EXITO: Baseline completada. {contador_archivos} archivos seguros registrados en BD.", flush=True)

def es_ruta_vigilada(ruta):
    """Determina si una ruta pertenece a una zona crítica vigilada,
    comparando por componentes de path completos (evita falsos
    positivos del tipo /etc vs /etcetera)."""
    ruta_norm = os.path.abspath(ruta)
    for base in PATHS_TO_WATCH:
        base_norm = os.path.abspath(base)
        if ruta_norm == base_norm or ruta_norm.startswith(base_norm + os.sep):
            return True
    return False

def esta_excluido(ruta):
    """Determina si una ruta está en la lista de exclusión estática."""
    ruta_norm = os.path.abspath(ruta)
    for prefijo in RUTAS_EXCLUIDAS:
        prefijo_norm = prefijo.rstrip("/")
        if ruta_norm == prefijo_norm or ruta_norm.startswith(prefijo_norm + os.sep):
            return True
    return False

def circuito_disponible():
    """Cortacircuitos por tasa. Registra el intento de cuarentena y
    devuelve False (circuito abierto) si se superó el umbral de
    eventos permitidos en la ventana configurada. Se autorrestablece
    solo cuando la tasa de eventos baja."""
    ahora = time.time()
    with _lock_circuito:
        _historial_cuarentenas.append(ahora)
        while _historial_cuarentenas and ahora - _historial_cuarentenas[0] > VENTANA_SEGUNDOS:
            _historial_cuarentenas.popleft()
        return len(_historial_cuarentenas) <= UMBRAL_CUARENTENAS

def procesar_contencion(filepath, nombre_archivo):
    """Punto único de decisión sobre si un archivo debe ser
    cuarentenado. Centraliza vigilancia de rutas, exclusión estática
    y cortacircuitos por tasa para los tres manejadores de eventos."""
    if not es_ruta_vigilada(filepath):
        return None

    if esta_excluido(filepath):
        log_to_db(nombre_archivo, filepath, None, None, 'EXCLUIDO_POR_POLITICA',
                   "Ruta excluida de la contención automática (RUTAS_EXCLUIDAS)",
                   "desconocido", "desconocido")
        print(f"  EXCLUIDO: {nombre_archivo} está en RUTAS_EXCLUIDAS, no se cuarentena.", flush=True)
        return None

    if not circuito_disponible():
        log_to_db(nombre_archivo, filepath, None, None, 'CIRCUITO_ABIERTO',
                   "Cortacircuitos por tasa activo: cuarentena automática suspendida temporalmente",
                   "desconocido", "desconocido")
        print(f"  CORTACIRCUITOS: {nombre_archivo} NO fue cuarentenado (modo solo alerta activo).", flush=True)
        return None

    return cuarentenar_archivo(filepath, nombre_archivo)

def cuarentenar_archivo(filepath, nombre_archivo):
    if not os.path.exists(filepath):
        return None #El archivo ya fue cuarentenado por otro evento
    try:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        nombre_seguro = f"{nombre_archivo}_{timestamp}.infectado"
        ruta_cuarentena = os.path.join("/cuarentena", nombre_seguro)

        # Movemos el archivo a la ruata de cuarentena
        shutil.move(filepath, ruta_cuarentena)
        print(f"  IPS ACTIVO: {nombre_archivo} movido a {ruta_cuarentena}", flush=True)
        return ruta_cuarentena
    except Exception as e:
        print(f"Error al cuarentenar {filepath}: {e}", flush=True)
        return None


#--- MANEJADOR DE EVENTOS ---
class FIMEventHandler(FileSystemEventHandler):
    def on_created(self,event):
        if not event.is_directory:
            h_sha256, h_md5 = get_hashes(event.src_path)
            propietario, permisos = obtener_metadatos(event.src_path)
            nombre = event.src_path.split('/')[-1]
            memoria_archivos[event.src_path] = leer_archivo_texto(event.src_path)
            log_to_db(nombre,event.src_path, h_sha256, h_md5,'CREADO', "", propietario, permisos)

            procesar_contencion(event.src_path, nombre)

    def on_modified(self, event):
        if not event.is_directory:
            h_sha256, h_md5 = get_hashes(event.src_path)
            propietario, permisos = obtener_metadatos(event.src_path)
            nombre = event.src_path.split('/')[-1]

            lineas_nuevas = leer_archivo_texto(event.src_path)
            lineas_viejas = memoria_archivos.get(event.src_path, [])

            texto_diff = ""
            if lineas_viejas:
                diff_gen = difflib.unified_diff(lineas_viejas, lineas_nuevas, fromfile='Antes', tofile='Ahora')
                texto_diff = ''.join(list(diff_gen))
            else:
                texto_diff = "Contenido modificado. (Sin Registro previo en memoria para comparar)"

            memoria_archivos[event.src_path] = lineas_nuevas
            log_to_db(nombre, event.src_path, h_sha256, h_md5, 'MODIFICADO', texto_diff, propietario, permisos)
            print(f"EXITO: MODIFICADO con diff guardado -> {nombre}", flush=True)

            procesar_contencion(event.src_path, nombre)

    def on_deleted(self,event):
        if not event.is_directory:
            nombre = event.src_path.split('/')[-1]
            if event.src_path in memoria_archivos:
                del memoria_archivos[event.src_path]
            log_to_db(nombre, event.src_path, None, None, 'ELIMINADO', "Archivo eliminado del sistema", "desconocido", "desconocido")

    def on_moved(self, event):
        print(f"INTENTO DE MOVIDO: Origen = {event.src_path} Destino = {event.dest_path}", flush = True)
        try:
            h_sha256, h_md5 = get_hashes(event.dest_path)
            propietario, permisos = obtener_metadatos(event.dest_path)
            nombre = event.dest_path.split('/')[-1]
            if event.src_path in memoria_archivos:
                memoria_archivos[event.dest_path] = memoria_archivos.pop(event.src_path)
            log_to_db(nombre, event.dest_path, h_sha256, h_md5, 'MOVIDO', f"Movido desde: {event.src_path}", propietario, permisos)
            print(f"EXITO: MOVIDO guardado en BD -> {nombre}", flush=True)
            procesar_contencion(event.dest_path, nombre)
        except Exception as e:
            print(f"ERROR PROCESANDO MOVIDO: {e}", flush=True)

#--- INICIO DEL PROGRAMA ---
if __name__ == "__main__":
    generar_baseline()

    event_handler = FIMEventHandler()
    observer = Observer()

    # Le asignamos un vigilante a cada ruta de nuestra lista
    for path in PATHS_TO_WATCH:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)

    observer.start()
    print(f"Motor FIM iniciado. Zonas segurizadas: {PATHS_TO_WATCH}", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
