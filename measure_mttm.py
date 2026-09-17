#!/usr/bin/env python3
"""
measure_mttm.py

Creación de archivos en un directorio vigilado por `monitor.py` y medición
del MTTM usando el archivo `/tmp/timestamps_mttm_fin.csv` que escribe
`monitor.py` al cuarentenar. Genera un CSV con las 30 mediciones.

Uso recomendado (ejecutar como root en la VM donde corre el monitor):
python3 measure_mttm.py --target-dir /etc --trials 30
"""
import argparse
import os
import time
import csv
import sys


def ensure_file(path):
    try:
        dirp = os.path.dirname(path)
        if dirp and not os.path.exists(dirp):
            os.makedirs(dirp, exist_ok=True)
        open(path, 'a').close()
    except Exception:
        pass


def main():
    p = argparse.ArgumentParser(description="Medir MTTM usando monitor.py")
    p.add_argument("--target-dir", default="/etc", help="Directorio vigilado por el monitor donde crear archivos")
    p.add_argument("--trials", type=int, default=30, help="Número de mediciones a realizar")
    p.add_argument("--out", default="mttm_results.csv", help="CSV de salida")
    p.add_argument("--timestamps-file", default="/tmp/timestamps_mttm_fin.csv", help="Archivo donde el monitor anota cuarentenas")
    p.add_argument("--interval", type=float, default=2.0, help="Segundos entre pruebas (protocolo)")
    p.add_argument("--timeout", type=float, default=60.0, help="Timeout en segundos para cada medición")
    args = p.parse_args()

    if not os.path.isdir(args.target_dir):
        print(f"ERROR: target-dir {args.target_dir} no existe o no es un directorio", file=sys.stderr)
        sys.exit(2)

    ensure_file(args.timestamps_file)

    # Posicion inicial para leer solo nuevas líneas
    pos = 0
    try:
        pos = os.path.getsize(args.timestamps_file)
    except Exception:
        pos = 0

    results = []

    print(f"Iniciando {args.trials} mediciones de MTTM en {args.target_dir}. Salida: {args.out}")

    for i in range(args.trials):
        name = f"mttm_probe_{int(time.time()*1e6)}_{i}.test"
        path = os.path.join(args.target_dir, name)

        t0 = time.time_ns()

        try:
            with open(path, 'w') as f:
                f.write('mttm_probe\n')
                f.flush()
                os.fsync(f.fileno())
            print(f"[{i+1}/{args.trials}] Archivo creado: {path}")
        except Exception as e:
            print(f"ERROR creando archivo {path}: {e}", file=sys.stderr)
            results.append((name, t0, None, None, 'create_error'))
            time.sleep(args.interval)
            continue

        matched = False
        deadline = time.time() + args.timeout

        while time.time() < deadline:
            try:
                with open(args.timestamps_file, 'r') as tf:
                    tf.seek(pos)
                    new = tf.read()
                    pos = tf.tell()
                    if new:
                        for line in new.splitlines():
                            parts = line.strip().split(',', 1)
                            if len(parts) != 2:
                                continue
                            bn, ts = parts[0], parts[1]
                            if bn == name:
                                try:
                                    q_ts_ns = int(ts)
                                    delta_ms = (q_ts_ns - t0) / 1e6
                                except Exception:
                                    q_ts_ns = None
                                    delta_ms = None
                                results.append((name, t0, q_ts_ns, delta_ms, 'ok'))
                                print(f"  -> Cuarentenado. MTTM = {delta_ms:.3f} ms")
                                matched = True
                                break
                    
            except FileNotFoundError:
                # el monitor aun no creó el archivo, seguir esperando
                pass
            except Exception as e:
                print(f"WARN: lectura timestamps: {e}", file=sys.stderr)

            if matched:
                break
            time.sleep(0.1)

        if not matched:
            print(f"  -> TIMEOUT ({args.timeout}s): no se encontró registro de cuarentena para {name}")
            results.append((name, t0, None, None, 'timeout'))

        time.sleep(args.interval)

    # Escribir CSV de resultados
    with open(args.out, 'w', newline='') as csvf:
        writer = csv.writer(csvf)
        writer.writerow(['name', 'created_ns', 'quarantine_ns', 'mttm_ms', 'status'])
        for row in results:
            writer.writerow(row)

    print(f"Mediciones completadas. {len(results)} filas escritas en {args.out}")
    # Mostrar serie cruda (mttm_ms)
    valores = [r[3] for r in results if r[3] is not None]
    print("Serie (ms):", ','.join(f"{v:.3f}" for v in valores))


if __name__ == '__main__':
    main()
