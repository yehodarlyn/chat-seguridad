# para que funcione el archivo necesitas instalar cryptography
# pip install cryptography

import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Aqui le guardamos las llaves del servidor
LLAVE_PRIVADA = "server_private.pem"
LLAVE_PUBLICA = "server_public.pem"


def generar_llaves():
    # Generamos un par de llaves
    llave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Guardamos la llave privada en un archivo
    with open(LLAVE_PRIVADA, "wb") as f:
        f.write(llave_privada.private_bytes(
            
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Guardamos la llave publica en otro archivo
    with open(LLAVE_PUBLICA, "wb") as f:
        f.write(llave_privada.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def cargar_llave_privada():
    # Si no existen las llaves las generamos
    if not os.path.exists(LLAVE_PRIVADA):
        generar_llaves()

    with open(LLAVE_PRIVADA, "rb") as f:

        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def cargar_llave_publica_bytes():
    # Si no existen las llaves las generamos
    if not os.path.exists(LLAVE_PUBLICA):
        generar_llaves()

    with open(LLAVE_PUBLICA, "rb") as f:
        return f.read()


def descifrar_mensaje(mensaje_cifrado):

    # Cargamos la llave privada del servidor

    llave_privada = cargar_llave_privada()

    try:
        # Decodificamos el mensaje de base64 y lo desciframos
        mensaje_bytes = base64.b64decode(mensaje_cifrado)
        mensaje_original = llave_privada.decrypt(
            mensaje_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),

                label=None
            )
        )
        return mensaje_original.decode("utf-8")
    except Exception as e:
        print(f"Error al descifrar: {e}")
        return ""


def cifrar_mensaje(mensaje, llave_publica_pem):
    # se carga la llave publica del cliente
    llave_publica = serialization.load_pem_public_key(llave_publica_pem, backend=default_backend())

    # ciframos el mensaje
    mensaje_cifrado = llave_publica.encrypt(
        mensaje.encode("utf-8"),
        padding.OAEP(

            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # regresamos el mensaje cifrado en base64 para poder enviarlo
    return base64.b64encode(mensaje_cifrado).decode("utf-8")
