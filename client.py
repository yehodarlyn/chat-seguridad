"""
client.py
Cliente de chat TCP con:
  - Intercambio de llaves RSA (criptografía asimétrica).
  - Registro o login interactivo.
  - Mensajes públicos y privados cifrados.
  - Visualización con fecha/hora y nombre de usuario.
  - Hilo de escucha independiente para recepción en tiempo real.
  - Bitácora en logs/cliente.log.
  - Validación local de entradas.
"""

import json
import logging
import socket
import threading
from datetime import datetime

from crypto import (
    cifrar_mensaje,
    descifrar_mensaje,
    deserializar_llave_publica,
    generar_par_llaves,
    serializar_llave_publica,
)
from logger_config import configurar_logger

# ── Configuración ─────────────────────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 5555
BUFFER = 8192

configurar_logger("cliente.log")

# Par de llaves RSA del cliente
_llave_privada, _llave_publica = generar_par_llaves()
_llave_publica_srv = None        # Se rellena durante el handshake


# ── Utilidades ────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _enviar(sock: socket.socket, payload: str) -> None:
    """Envía un string terminado en newline."""
    sock.sendall((payload + "\n").encode("utf-8"))


def _enviar_cifrado(sock: socket.socket, texto: str) -> None:
    """Cifra texto con la llave pública del servidor y lo envía."""
    global _llave_publica_srv
    payload = cifrar_mensaje(texto, _llave_publica_srv)
    _enviar(sock, f"ENC:{payload}")


def _recibir_linea(sock: socket.socket) -> str:
    """Lee bytes hasta '\n'. Devuelve '' si se cierra la conexión."""
    fragmentos = []
    while True:
        byte = sock.recv(1)
        if not byte:
            return ""
        if byte == b"\n":
            break
        fragmentos.append(byte)
    return b"".join(fragmentos).decode("utf-8", errors="replace").strip()


def _descifrar_linea(linea: str) -> str | None:
    """Si la línea es 'ENC:...', la descifra y devuelve el texto plano."""
    if linea.startswith("ENC:"):
        try:
            return descifrar_mensaje(linea[4:], _llave_privada)
        except Exception as e:
            logging.warning(f"No se pudo descifrar mensaje del servidor: {e}")
            return None
    return linea   # mensajes en claro durante el handshake (PUBKEY:)


def _imprimir(msg: str) -> None:
    """Imprime un mensaje con formato claro en consola."""
    print(f"\r{msg}\n> ", end="", flush=True)


# ── Intercambio de llaves ─────────────────────────────────────────────────────

def _handshake(sock: socket.socket) -> bool:
    """
    Intercambia llaves RSA con el servidor.
    Devuelve True si el handshake fue exitoso.
    """
    global _llave_publica_srv

    linea = _recibir_linea(sock)
    if not linea.startswith("PUBKEY:"):
        print("[Error] Handshake inválido: no se recibió llave pública del servidor.")
        return False

    pem_srv = linea[len("PUBKEY:"):]
    try:
        _llave_publica_srv = deserializar_llave_publica(pem_srv)
    except Exception as e:
        print(f"[Error] Llave pública del servidor inválida: {e}")
        return False

    # Enviar nuestra llave pública al servidor
    pem_cliente = serializar_llave_publica(_llave_publica)
    _enviar(sock, f"PUBKEY:{pem_cliente}")
    logging.info("Handshake RSA completado con el servidor.")
    return True


# ── Autenticación ─────────────────────────────────────────────────────────────

def _pedir_credenciales() -> dict:
    """Solicita al usuario sus datos de autenticación de forma interactiva."""
    print("\n╔══════════════════════════════╗")
    print("║      CHAT SEGURO TCP         ║")
    print("╚══════════════════════════════╝")
    print("  [1] Iniciar sesión (login)")
    print("  [2] Registrarse (registro)")

    while True:
        opcion = input("  Opción: ").strip()
        if opcion in ("1", "2"):
            break
        print("  Opción inválida. Elige 1 o 2.")

    accion = "login" if opcion == "1" else "registro"

    while True:
        username = input("  Usuario: ").strip()
        if 3 <= len(username) <= 20 and username.replace("_", "").isalnum():
            break
        print("  Usuario inválido (3-20 caracteres, letras/números/guion_bajo).")

    import getpass
    while True:
        password = getpass.getpass("  Contraseña: ")
        if len(password) >= 6:
            break
        print("  La contraseña debe tener al menos 6 caracteres.")

    return {"accion": accion, "usuario": username, "password": password}


def _autenticar(sock: socket.socket) -> bool:
    """Espera el CMD:AUTH del servidor y responde con las credenciales cifradas."""
    # Esperar CMD:AUTH cifrado
    linea = _recibir_linea(sock)
    texto = _descifrar_linea(linea)
    if texto != "CMD:AUTH":
        print(f"[Error] Protocolo inesperado: {texto}")
        return False

    credenciales = _pedir_credenciales()
    _enviar_cifrado(sock, json.dumps(credenciales, ensure_ascii=False))

    # Leer respuesta
    respuesta = _recibir_linea(sock)
    texto_resp = _descifrar_linea(respuesta) or ""

    if texto_resp.startswith("OK:"):
        print(f"\n✔ {texto_resp[3:]}")
        logging.info(f"Autenticación exitosa como '{credenciales['usuario']}'")
        return True
    elif texto_resp.startswith("ERROR:"):
        print(f"\n✘ {texto_resp[6:]}")
        logging.warning(f"Autenticación fallida: {texto_resp[6:]}")
        return False
    else:
        print(f"\n[?] Respuesta inesperada: {texto_resp}")
        return False


# ── Hilo de escucha ───────────────────────────────────────────────────────────

def _escuchar(sock: socket.socket, evento_salida: threading.Event) -> None:
    """Recibe y muestra mensajes del servidor en un hilo dedicado."""
    while not evento_salida.is_set():
        try:
            linea = _recibir_linea(sock)
            if not linea:
                _imprimir("[Servidor] Conexión cerrada.")
                evento_salida.set()
                break
            texto = _descifrar_linea(linea)
            if texto:
                _imprimir(texto)
                logging.info(f"Recibido: {texto}")
        except Exception as e:
            if not evento_salida.is_set():
                logging.error(f"Error en hilo de escucha: {e}")
            break


# ── Ayuda en línea ────────────────────────────────────────────────────────────

AYUDA = """
Comandos disponibles:
  /msg <usuario> <texto>  → Enviar mensaje privado
  /usuarios               → Ver usuarios conectados
  /ayuda                  → Mostrar esta ayuda
  /salir                  → Desconectarse del servidor
"""


# ── Loop principal del cliente ────────────────────────────────────────────────

def iniciar_cliente() -> None:
    global _llave_publica_srv

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((HOST, PORT))
            print(f"[*] Conectado al servidor {HOST}:{PORT}")
            logging.info(f"Conectado a {HOST}:{PORT}")
        except ConnectionRefusedError:
            print(f"[Error] No se pudo conectar a {HOST}:{PORT}. ¿Está el servidor activo?")
            return

        # 1. Handshake RSA
        if not _handshake(sock):
            return

        # 2. Autenticación
        if not _autenticar(sock):
            return

        print(AYUDA)
        print("─" * 40)

        # 3. Hilo de escucha
        evento_salida = threading.Event()
        hilo_rx = threading.Thread(
            target=_escuchar,
            args=(sock, evento_salida),
            name="Receptor",
            daemon=True,
        )
        hilo_rx.start()

        # 4. Loop de envío
        while not evento_salida.is_set():
            try:
                entrada = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Saliendo...")
                evento_salida.set()
                break

            if not entrada:
                continue

            if entrada == "/salir":
                print("[*] Desconectando...")
                evento_salida.set()
                break

            if entrada == "/ayuda":
                print(AYUDA)
                continue

            # Validar longitud máxima
            if len(entrada) > 1000:
                print("[!] Mensaje demasiado largo (máx. 1000 caracteres).")
                continue

            try:
                _enviar_cifrado(sock, entrada)
                logging.info(f"Mensaje enviado: {entrada[:60]}{'...' if len(entrada)>60 else ''}")
            except Exception as e:
                logging.error(f"Error al enviar mensaje: {e}")
                print(f"[Error] No se pudo enviar el mensaje: {e}")
                evento_salida.set()
                break

    print("[*] Conexión terminada.")


if __name__ == "__main__":
    iniciar_cliente()