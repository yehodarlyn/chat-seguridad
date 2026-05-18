import json
import os
import bcrypt

USERS_FILE = "server/users.json"


def _cargar_usuarios():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def _guardar_usuarios(usuarios):
    with open(USERS_FILE, "w") as f:
        json.dump(usuarios, f, indent=2)


def registrar_usuario(username, password):
    usuarios = _cargar_usuarios()

    if username in usuarios:
        return False, "El usuario ya existe"

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    usuarios[username] = {
        "password": hashed.decode()
    }
    _guardar_usuarios(usuarios)
    return True, "Registro exitoso"


def validar_login(username, password):
    usuarios = _cargar_usuarios()

    if username not in usuarios:
        return False, "Usuario no encontrado"

    hashed = usuarios[username]["password"].encode()
    if bcrypt.checkpw(password.encode(), hashed):
        return True, "Login exitoso"
    else:
        return False, "Contraseña incorrecta"
