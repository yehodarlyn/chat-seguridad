"""
server.py
Servidor de chat TCP multihilo con:
  - Autenticación (registro / login) con contraseñas hasheadas.
  - Cifrado híbrido RSA-2048 + AES-256-GCM extremo a extremo.
  - Mensajes públicos y privados con fecha/hora.
  - Máximo 5 conexiones simultáneas.
  - Bitácora de eventos en logs/servidor.log.
  - Validación y sanitización de entradas.
"""

import json
import logging
import socket
import threading
from datetime import datetime

from auth import registrar_usuario, validar_login, validar_nombre_usuario
from crypto import (
    descifrar_mensaje,
    cifrar_mensaje,
    deserializar_llave_publica,
    generar_par_llaves,
    serializar_llave_publica,
)
from logger_config import configurar_logger

# ── Configuración ─────────────────────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 5555
MAX_CLIENTES = 5
BUFFER = 8192

configurar_logger("servidor.log")

# Llave RSA del servidor (para el canal de autenticación inicial)
_llave_privada_srv, _llave_publica_srv = generar_par_llaves()

# Registro de clientes activos
# { conn: {"usuario": str, "llave_publica": RSAPublicKey} }
clientes: dict = {}
lock = threading.Lock()


# ── Utilidades ────────────────────────────────────────────────────────────────

def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _sanitizar(texto: str, max_len: int = 1000) -> str:
    """Elimina caracteres de control y trunca el texto."""
    limpio = "".join(c for c in texto if c >= " " or c in "\t")
    return limpio[:max_len]


def _enviar(conn: socket.socket, payload: str) -> None:
    """Envía un string terminado en newline."""
    try:
        conn.sendall((payload + "\n").encode("utf-8"))
    except OSError:
        pass


def _enviar_cifrado(conn: socket.socket, texto: str, llave_publica) -> None:
    """Cifra `texto` con la llave pública del cliente y lo envía."""
    try:
        payload = cifrar_mensaje(texto, llave_publica)
        _enviar(conn, f"ENC:{payload}")
    except Exception as e:
        logging.error(f"Error al cifrar mensaje saliente: {e}")


def _recibir_linea(conn: socket.socket) -> str:
    """Lee hasta newline; devuelve string vacío si se cierra la conexión."""
    fragmentos = []
    while True:
        byte = conn.recv(1)
        if not byte:
            return ""
        if byte == b"\n":
            break
        fragmentos.append(byte)
    return b"".join(fragmentos).decode("utf-8", errors="replace").strip()


# ── Broadcast y mensajería ───────────────────────────────────────────────────

def broadcast(texto: str, excluir_conn=None) -> None:
    """Envía un mensaje (cifrado) a todos los clientes salvo el excluido."""
    with lock:
        snapshot = dict(clientes)
    for conn, datos in snapshot.items():
        if conn != excluir_conn:
            _enviar_cifrado(conn, texto, datos["llave_publica"])


def enviar_privado(destino_usuario: str, texto: str) -> bool:
    """Envía un mensaje cifrado solo al usuario destino. Devuelve True si existe."""
    with lock:
        snapshot = dict(clientes)
    for conn, datos in snapshot.items():
        if datos["usuario"] == destino_usuario:
            _enviar_cifrado(conn, texto, datos["llave_publica"])
            return True
    return False


# ── Handshake de llaves ──────────────────────────────────────────────────────

def _intercambiar_llaves(conn: socket.socket):
    """
    Protocolo de intercambio de llaves:
      1. Servidor envía su llave pública PEM.
      2. Cliente envía su llave pública PEM.
    Devuelve la llave pública RSA del cliente o None si falla.
    """
    try:
        pem_srv = serializar_llave_publica(_llave_publica_srv)
        _enviar(conn, f"PUBKEY:{pem_srv}")

        linea = _recibir_linea(conn)
        if not linea.startswith("PUBKEY:"):
            return None
        pem_cliente = linea[len("PUBKEY:"):]
        return deserializar_llave_publica(pem_cliente)
    except Exception as e:
        logging.error(f"Error en intercambio de llaves: {e}")
        return None


# ── Autenticación ────────────────────────────────────────────────────────────

def _autenticar(conn: socket.socket, llave_publica_cliente) -> str | None:
    """
    Realiza el flujo de autenticación cifrada.
    Devuelve el nombre de usuario autenticado o None si falla.
    """
    _enviar_cifrado(conn, "CMD:AUTH", llave_publica_cliente)

    # Recibir JSON de credenciales (cifrado por el cliente)
    linea = _recibir_linea(conn)
    if not linea.startswith("ENC:"):
        return None

    try:
        datos_raw = descifrar_mensaje(linea[4:], _llave_privada_srv)
        datos_auth = json.loads(datos_raw)
    except Exception as e:
        logging.warning(f"No se pudo descifrar/parsear credenciales: {e}")
        _enviar_cifrado(conn, "ERROR:Formato de autenticación inválido", llave_publica_cliente)
        return None

    accion   = datos_auth.get("accion", "").strip()
    username = datos_auth.get("usuario", "").strip()
    password = datos_auth.get("password", "")

    # Sanitización básica
    username = _sanitizar(username, 20)
    password = _sanitizar(password, 128)

    # Validar nombre de usuario
    ok, msg = validar_nombre_usuario(username)
    if not ok:
        _enviar_cifrado(conn, f"ERROR:{msg}", llave_publica_cliente)
        return None

    if len(password) < 6:
        _enviar_cifrado(conn, "ERROR:La contraseña debe tener al menos 6 caracteres.", llave_publica_cliente)
        return None

    if accion == "registro":
        ok, msg = registrar_usuario(username, password)
    elif accion == "login":
        ok, msg = validar_login(username, password)
    else:
        _enviar_cifrado(conn, "ERROR:Acción desconocida (use 'login' o 'registro').", llave_publica_cliente)
        return None

    if not ok:
        _enviar_cifrado(conn, f"ERROR:{msg}", llave_publica_cliente)
        logging.warning(f"Auth fallida [{accion}] usuario='{username}'")
        return None

    _enviar_cifrado(conn, f"OK:{msg}", llave_publica_cliente)
    return username


# ── Hilo por cliente ─────────────────────────────────────────────────────────

def manejar_cliente(conn: socket.socket, addr: tuple) -> None:
    usuario = None
    llave_publica_cliente = None

    try:
        logging.info(f"Nueva conexión desde {addr}")

        # 1. Intercambio de llaves
        llave_publica_cliente = _intercambiar_llaves(conn)
        if llave_publica_cliente is None:
            logging.warning(f"Intercambio de llaves fallido con {addr}")
            return

        # 2. Autenticación
        with lock:
            if len(clientes) >= MAX_CLIENTES:
                _enviar_cifrado(conn, "ERROR:Servidor lleno (máximo 5 clientes).", llave_publica_cliente)
                logging.warning(f"Conexión rechazada (servidor lleno): {addr}")
                return

        username = _autenticar(conn, llave_publica_cliente)
        if username is None:
            return

        # 3. Registrar cliente
        with lock:
            # Doble verificación tras adquirir el lock
            if len(clientes) >= MAX_CLIENTES:
                _enviar_cifrado(conn, "ERROR:Servidor lleno (máximo 5 clientes).", llave_publica_cliente)
                return
            # Verificar que el usuario no esté ya conectado
            conectados = [d["usuario"] for d in clientes.values()]
            if username in conectados:
                _enviar_cifrado(conn, "ERROR:Este usuario ya está conectado.", llave_publica_cliente)
                return
            clientes[conn] = {"usuario": username, "llave_publica": llave_publica_cliente}

        usuario = username
        logging.info(f"Sesión iniciada: '{usuario}' desde {addr}")

        entrada = f"[{_timestamp()}] [Servidor] {usuario} se unió al chat."
        broadcast(entrada, excluir_conn=conn)

        # 4. Loop de mensajes
        while True:
            linea = _recibir_linea(conn)
            if not linea:
                break

            # Descifrar mensaje entrante
            if linea.startswith("ENC:"):
                try:
                    mensaje_raw = descifrar_mensaje(linea[4:], _llave_privada_srv)
                except Exception as e:
                    logging.warning(f"Error al descifrar mensaje de '{usuario}': {e}")
                    _enviar_cifrado(conn, "ERROR:Mensaje corrupto o inválido.", llave_publica_cliente)
                    continue
            else:
                # Rechazar mensajes en claro (forzar cifrado)
                _enviar_cifrado(conn, "ERROR:Solo se aceptan mensajes cifrados.", llave_publica_cliente)
                continue

            mensaje_raw = _sanitizar(mensaje_raw)
            if not mensaje_raw:
                continue

            ts = _timestamp()

            # Comando /msg para mensaje privado
            if mensaje_raw.startswith("/msg "):
                partes = mensaje_raw.split(" ", 2)
                if len(partes) < 3:
                    _enviar_cifrado(conn, "ERROR:Uso: /msg <usuario> <mensaje>", llave_publica_cliente)
                    continue
                destino = _sanitizar(partes[1], 20)
                texto   = _sanitizar(partes[2])

                if destino == usuario:
                    _enviar_cifrado(conn, "ERROR:No puedes enviarte un mensaje privado a ti mismo.", llave_publica_cliente)
                    continue

                msg_privado = f"[{ts}] [Privado de {usuario}]: {texto}"
                copia_remitente = f"[{ts}] [Privado → {destino}]: {texto}"

                if enviar_privado(destino, msg_privado):
                    _enviar_cifrado(conn, copia_remitente, llave_publica_cliente)
                    logging.info(f"Mensaje privado: '{usuario}' → '{destino}'")
                else:
                    _enviar_cifrado(conn, f"ERROR:Usuario '{destino}' no encontrado o no conectado.", llave_publica_cliente)

            # Comando /usuarios para listar conectados
            elif mensaje_raw.strip() == "/usuarios":
                with lock:
                    lista = [d["usuario"] for d in clientes.values()]
                _enviar_cifrado(conn, f"[{ts}] [Servidor] Conectados: {', '.join(lista)}", llave_publica_cliente)

            # Mensaje público
            else:
                msg_pub = f"[{ts}] {usuario}: {mensaje_raw}"
                logging.info(f"Mensaje público de '{usuario}'")
                broadcast(msg_pub, excluir_conn=conn)
                # Confirmar al remitente (eco propio)
                _enviar_cifrado(conn, f"[{ts}] [Tú]: {mensaje_raw}", llave_publica_cliente)

    except Exception as e:
        logging.error(f"Error inesperado con {addr}: {e}", exc_info=True)
    finally:
        with lock:
            clientes.pop(conn, None)
        conn.close()
        if usuario:
            salida = f"[{_timestamp()}] [Servidor] {usuario} se desconectó."
            broadcast(salida)
            logging.info(f"Desconexión: '{usuario}' desde {addr}")


# ── Punto de entrada ─────────────────────────────────────────────────────────

def iniciar_servidor() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(MAX_CLIENTES)
        logging.info(f"Servidor escuchando en {HOST}:{PORT}")
        print(f"[Servidor] Escuchando en {HOST}:{PORT}  |  Máx. clientes: {MAX_CLIENTES}")

        while True:
            conn, addr = srv.accept()
            hilo = threading.Thread(
                target=manejar_cliente,
                args=(conn, addr),
                name=f"Cliente-{addr[1]}",
                daemon=True,
            )
            hilo.start()


if __name__ == "__main__":
    iniciar_servidor()