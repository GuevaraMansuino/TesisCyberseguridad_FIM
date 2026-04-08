import time
import hashlib
import psycopg2
import difflib
import os
import shutil
import pwd # Sirve para traducir el ID de usuario al nombre (ej: root)
import stat # Sirver para leer los permisos (ej: chmod 755)

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

#--- CONFIGURACION ---
DB_HOST = "localhost"
DB_NAME = "fim_db"
DB_USER = "fim_user"
DB_PASS = "291020"
PATHS_TO_WATCH = ["/etc", "/root", "/usr/bin"]

#--- MEMORIA RAM PARA EL DIFF ---
memoria_archivos = {}

def leer_archivo_texto(ruta):
    try:
        # Leemos el archivo tolerando caracteres raros por si es un binario
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

def cuarentenar_archivo(filepath, nombre_archivo):
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

            # Revisamos si la ruta del evento empieza con alguna de nuestras carpetas vigiladas
            if any(event.src_path.startswith(p) for p in PATHS_TO_WATCH):
                cuarentenar_archivo(event.src_path, nombre)

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

            # Revisamos si la ruta del evento empieza con alguna de nuestras carpetas vigiladas
            if any(event.src_path.startswith(p) for p in PATHS_TO_WATCH):
                cuarentenar_archivo(event.src_path, nombre)

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
            log_to_db(nombre, event.dest_path, h, 'MOVIDO',  "Movido desde: {event.src_path}", propietario, permisos)
            print(f"EXITO: MOVIDO guardado en BD -> {nombre}", flush=True)
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