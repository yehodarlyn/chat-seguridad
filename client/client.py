import socket
import threading
import json
from datetime import datetime
from crypto import generar_llaves, serializar_publica, descifrar_mensaje

HOST = '127.0.0.1'
PORT = 5555

llave_privada, llave_publica = generar_llaves()


def timestamp():
    return datetime.now().strftime("%H:%M:%S")


def recibir_mensajes(conn):
    """Hilo que escucha mensajes entrantes del servidor"""
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("\n[Servidor desconectado]")
                break

            mensaje = data.decode().strip()

            if mensaje == "CMD:AUTH":
                continue

            print(f"\n[{timestamp()}] {mensaje}")
            print(">> ", end="", flush=True)

        except Exception as e:
            print(f"\n[Error de conexion]: {e}")
            break


def autenticar(conn):
    """Espera CMD:AUTH y envia credenciales"""
    data = conn.recv(4096).decode()
    if data != "CMD:AUTH":
        print("Error: respuesta inesperada del servidor")
        return False

    print("\n=== Chat Seguro ===")
    print("1. Iniciar sesion")
    print("2. Registrarse")
    opcion = input("Elige una opcion (1/2): ").strip()

    if opcion == "1":
        accion = "login"
    elif opcion == "2":
        accion = "registro"
    else:
        print("Opcion invalida")
        return False

    usuario  = input("Usuario: ").strip()
    password = input("Contraseña: ").strip()

    payload = json.dumps({
        "accion":   accion,
        "usuario":  usuario,
        "password": password
    })
    conn.sendall(payload.encode())

    respuesta = conn.recv(4096).decode()
    if respuesta.startswith("OK:"):
        print(f"\n✓ {respuesta[3:]}")
        return True
    elif respuesta.startswith("ERROR:"):
        print(f"\n✗ {respuesta[6:]}")
        return False
    return False


def mostrar_ayuda():
    print("""
--- Comandos disponibles ---
  /msg <usuario> <texto>   Mensaje privado
  /ayuda                   Ver esta ayuda
  /salir                   Desconectarse
----------------------------""")


def iniciar_cliente():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        try:
            conn.connect((HOST, PORT))
        except ConnectionRefusedError:
            print("No se pudo conectar --> ¿Esta corriendo el servidor?")
            return

        if not autenticar(conn):
            return

        hilo = threading.Thread(target=recibir_mensajes, args=(conn,))
        hilo.daemon = True
        hilo.start()

        mostrar_ayuda()
        print(">> ", end="", flush=True)

        while True:
            try:
                mensaje = input()
            except (EOFError, KeyboardInterrupt):
                break

            mensaje = mensaje.strip()
            if not mensaje:
                continue

            if mensaje == "/salir":
                print("Desconectando...")
                break
            elif mensaje == "/ayuda":
                mostrar_ayuda()
                print(">> ", end="", flush=True)
                continue

            try:
                conn.sendall(mensaje.encode())
            except Exception as e:
                print(f"Error al enviar: {e}")
                break


if __name__ == "__main__":
    iniciar_cliente()
