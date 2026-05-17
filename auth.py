# para que funcione este archivo necesitas instalar bcrypt
# pip install bcrypt

import json
import os
import bcrypt

# Aqui guardamos los usuarios en un archivo json
ARCHIVO_USUARIOS = "users.json"


def cargar_usuarios():
    # Si el archivo no existe regresamos un diccionario vacio
    if not os.path.exists(ARCHIVO_USUARIOS):
        return {}
    with open(ARCHIVO_USUARIOS, "r") as f:
        return json.load(f)


def guardar_usuarios(usuarios):
    with open(ARCHIVO_USUARIOS, "w") as f:
        json.dump(usuarios, f)


def registrar_usuario(username, password):
    # Aqui checamos que el usuario no este vacio y que tenga minimo 3 letras
    if not username or len(username) < 3:
        return False, "El usuario debe tener al menos 3 caracteres"

    # La contrasena tiene q tener al menos 6 caracteres
    if not password or len(password) < 6:
        return False, "La contrasena debe tener al menos 6 caracteres"

    # Solo se pueden letras y numeros en el nombre de usuario
    if not username.isalnum():
        return False, "El usuario solo puede tener letras y numeros"

    usuarios = cargar_usuarios()

    # vemos que el usuario no exista ya
    if username in usuarios:
        return False, "Ese usuario ya existe, elige otro"

    # guardamos la contrasena con hash para no guardarla en puro texto
    hash_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    usuarios[username] = {"password": hash_password.decode()}

    guardar_usuarios(usuarios)
    return True, "Usuario registrado correctamente"


def validar_login(username, password):
    if not username or not password:
        return False, "Debes ingresar usuario y contrasena"

    usuarios = cargar_usuarios()

    # Verificamos que el usuario exista
    if username not in usuarios:
        return False, "Usuario o contrasena incorrectos"

    # Comparamos la contrasena con el hash guardado
    hash_guardado = usuarios[username]["password"].encode()
    if bcrypt.checkpw(password.encode(), hash_guardado):
        return True, f"Bienvenido {username}"
    else:
        return False, "Usuario o contrasena incorrectos"
