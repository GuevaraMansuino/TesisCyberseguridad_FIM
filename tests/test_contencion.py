"""
Tests unitarios para las funciones de decisión de contención del motor FIM-IPS.
Cubre: es_ruta_vigilada, esta_excluido, circuito_disponible.

Ejecutar con: pytest tests/test_contencion.py -v
"""
import time
import pytest

# Ajustar el import según dónde vivan estas funciones en tu repo real:
from monitor import (
    es_ruta_vigilada,
    esta_excluido,
    circuito_disponible,
    PATHS_TO_WATCH,
    RUTAS_EXCLUIDAS,
    UMBRAL_CUARENTENAS,
    VENTANA_SEGUNDOS,
)


# ---------------------------------------------------------------------------
# es_ruta_vigilada(ruta)
# PATHS_TO_WATCH = ["/etc", "/root", "/usr/bin"]
# ---------------------------------------------------------------------------

class TestEsRutaVigilada:

    def test_ruta_exacta_de_zona_vigilada(self):
        assert es_ruta_vigilada("/etc") is True

    def test_archivo_dentro_de_zona_vigilada(self):
        assert es_ruta_vigilada("/etc/passwd") is True

    def test_subdirectorio_profundo_dentro_de_zona_vigilada(self):
        assert es_ruta_vigilada("/etc/zona_a/subdir/archivo.txt") is True

    def test_ruta_fuera_de_toda_zona_vigilada(self):
        assert es_ruta_vigilada("/tmp/archivo.txt") is False

    def test_falso_positivo_por_prefijo_de_string(self):
        # Caso específico que la propia tesis dice resolver:
        # "/etcetera" NO debe matchear con "/etc" solo por ser prefijo de string.
        assert es_ruta_vigilada("/etcetera/archivo.txt") is False

    def test_ruta_relativa_se_normaliza_correctamente(self, monkeypatch, tmp_path):
        # Si la función usa os.path.abspath(), una ruta relativa ejecutada
        # desde dentro de /etc debería resolverse como vigilada.
        monkeypatch.chdir("/etc")
        assert es_ruta_vigilada("passwd") is True


# ---------------------------------------------------------------------------
# esta_excluido(ruta)
# ---------------------------------------------------------------------------

class TestEstaExcluido:

    def test_ruta_en_lista_de_exclusion(self):
        # Reemplazar "/etc/ruta_excluida_real" por un valor real de RUTAS_EXCLUIDAS
        ruta_excluida = next(iter(RUTAS_EXCLUIDAS))
        assert esta_excluido(ruta_excluida) is True

    def test_archivo_dentro_de_carpeta_excluida(self):
        ruta_excluida = next(iter(RUTAS_EXCLUIDAS))
        assert esta_excluido(f"{ruta_excluida}/archivo_interno.txt") is True

    def test_ruta_no_excluida(self):
        assert esta_excluido("/etc/zona_a/archivo_normal.txt") is False

    def test_lista_de_exclusion_vacia_no_excluye_nada(self, monkeypatch):
        monkeypatch.setattr("monitor.RUTAS_EXCLUIDAS", set())
        assert esta_excluido("/etc/lo_que_sea") is False


# ---------------------------------------------------------------------------
# circuito_disponible()
# VENTANA_SEGUNDOS = 30, UMBRAL_CUARENTENAS = 10
# ---------------------------------------------------------------------------

class TestCircuitoDisponible:

    def setup_method(self):
        # Limpiar el historial global antes de cada test para que no
        # queden eventos de un test contaminando al siguiente.
        import monitor
        monitor._historial_cuarentenas.clear()

    def test_circuito_cerrado_bajo_el_umbral(self):
        for _ in range(5):
            assert circuito_disponible() is True

    def test_circuito_se_abre_al_superar_el_umbral(self):
        resultados = [circuito_disponible() for _ in range(12)]
        # Las primeras UMBRAL_CUARENTENAS (10) deben ser True,
        # a partir de la 11ª debe devolver False.
        assert resultados[:10] == [True] * 10
        assert resultados[10] is False
        assert resultados[11] is False

    def test_circuito_se_autorrestablece_fuera_de_la_ventana(self, monkeypatch):
        import monitor
        # Saturar el circuito
        for _ in range(12):
            circuito_disponible()
        assert circuito_disponible() is False

        # Simular que pasaron 31 segundos (más que VENTANA_SEGUNDOS=30)
        tiempo_futuro = time.time() + 31
        monkeypatch.setattr("time.time", lambda: tiempo_futuro)

        assert circuito_disponible() is True
