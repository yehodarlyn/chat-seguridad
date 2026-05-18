from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def generar_llaves():
    """Genera par de llaves RSA. Llama esto en el cliente al iniciar."""
    llave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    llave_publica = llave_privada.public_key()
    return llave_privada, llave_publica


def serializar_publica(llave_publica):
    """Convierte llave pública a string para enviar por socket."""
    return llave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def deserializar_publica(pem_str):
    """Reconstruye llave pública desde string PEM."""
    return serialization.load_pem_public_key(pem_str.encode())


def cifrar_mensaje(mensaje, llave_publica):
    """Cifra un mensaje con la llave pública del destinatario."""
    return llave_publica.encrypt(
        mensaje.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def descifrar_mensaje(mensaje_cifrado, llave_privada):
    """Descifra un mensaje con tu llave privada."""
    return llave_privada.decrypt(
        mensaje_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
