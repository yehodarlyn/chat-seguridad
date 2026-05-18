import socket
import threading
import json
import logging
from auth import registrar_usuario, validar_login
from crypto import descifrar_mensaje
from logger_config import configurar_logger

HOST = '127.0.0.1'
PORT = 5555
MAX_CLIENTES = 5

configurar_logger()

clientes = {}       # { conn: {"usuario": str} }
lock = threading.Lock()


def broadcast(mensaje, excluir_conn=None):
    """Envia mensaje a todos los clientes conectados"""
    with lock:
        for conn in list(clientes):
            if conn != excluir_conn:
                try:
                    conn.sendall(mensaje.encode())
                except:
                    pass


def enviar_privado(destino_usuario, mensaje):
    """Envia mensaje solo al usuario destino"""
    with lock:
        for conn, datos in clientes.items():
            if datos["usuario"] == destino_usuario:
                try:
                    conn.sendall(mensaje.encode())
                except:
                    pass
                return True
    return False


def manejar_cliente(conn, addr):
    usuario = None
    try:
        # --- Autenticacion ---
        conn.sendall("CMD:AUTH".encode())
        datos_auth = json.loads(conn.recv(4096).decode())

        accion   = datos_auth.get("accion")
        username = datos_auth.get("usuario", "").strip()
        password = datos_auth.get("password", "")

        # validacion basica
        if not username or len(username) < 3 or not username.isalnum():
            conn.sendall("ERROR:Usuario invalido".encode())
            return
        if not password or len(password) < 4:
            conn.sendall("ERROR:Contraseña muy corta".encode())
            return

        if accion == "registro":
            ok, msg = registrar_usuario(username, password)
        elif accion == "login":
            ok, msg = validar_login(username, password)
        else:
            conn.sendall("ERROR:Accion desconocida".encode())
            return

        if not ok:
            conn.sendall(f"ERROR:{msg}".encode())
            logging.warning(f"Auth fallida [{accion}] usuario='{username}' desde {addr}")
            return

        # verificar liite de conexiones
        with lock:
            if len(clientes) >= MAX_CLIENTES:
                conn.sendall("ERROR:Servidor lleno (max 5)".encode())
                return
            clientes[conn] = {"usuario": username}

        usuario = username
        conn.sendall(f"OK:{msg}".encode())
        logging.info(f"Conexión exitosa: {usuario} desde {addr}")
        broadcast(f"[Servidor] {usuario} se unió al chat.", excluir_conn=conn)

        # --- Loop de mensajes ---
        while True:
            data = conn.recv(4096)
            if not data:
                break

            mensaje_raw = data.decode().strip()
            if not mensaje_raw:
                continue

            # mensaje privado:/msg destinatario texto
            if mensaje_raw.startswith("/msg "):
                partes = mensaje_raw.split(" ", 2)
                if len(partes) < 3:
                    conn.sendall("ERROR:Uso: /msg <usuario> <mensaje>".encode())
                    continue
                destino = partes[1]
                texto   = partes[2]
                enviado = enviar_privado(destino, f"[Privado de {usuario}]: {texto}")
                if not enviado:
                    conn.sendall(f"ERROR:Usuario '{destino}' no encontrado".encode())
                logging.info(f"Privado: {usuario} -> {destino}")
            else:
                #mensaje publico
                logging.info(f"Mensaje publico de {usuario}")
                broadcast(f"{usuario}: {mensaje_raw}", excluir_conn=conn)

    except Exception as e:
        logging.error(f"Error con {addr}: {e}")
    finally:
        with lock:
            clientes.pop(conn, None)
        conn.close()
        if usuario:
            broadcast(f"[Servidor] {usuario} se desconecto")
            logging.info(f"Desconexion: {usuario}")


def iniciar_servidor():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        logging.info(f"Servidor escuchando en {HOST}:{PORT}")
        print(f"Servidor iniciado en {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=manejar_cliente, args=(conn, addr))
            thread.daemon = True
            thread.start()


if __name__ == "__main__":
    iniciar_servidor()
