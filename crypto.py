"""
crypto.py
Criptografía híbrida RSA-2048 + AES-256-GCM para el chat.

Flujo:
  1. Cada parte genera un par de llaves RSA.
  2. Al conectar, intercambian llaves públicas.
  3. Para cada mensaje:
     a. Se genera una llave AES efímera de 256 bits.
     b. El mensaje se cifra con AES-256-GCM.
     c. La llave AES se cifra con la llave pública RSA del destinatario.
     d. Se envía: llave_aes_cifrada || nonce || tag || texto_cifrado  (todo en base64).
  4. El receptor descifra la llave AES con su llave privada RSA,
     luego descifra el mensaje con AES-GCM.
"""

import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Generación de llaves ─────────────────────────────────────────────────────

def generar_par_llaves() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Genera un par de llaves RSA-2048."""
    llave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return llave_privada, llave_privada.public_key()


def serializar_llave_publica(llave_publica: rsa.RSAPublicKey) -> str:
    """Convierte la llave pública a PEM en formato string."""
    return llave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def deserializar_llave_publica(pem: str) -> rsa.RSAPublicKey:
    """Reconstruye una llave pública desde su representación PEM."""
    return serialization.load_pem_public_key(pem.encode("utf-8"))


# ── Cifrado / Descifrado ─────────────────────────────────────────────────────

def cifrar_mensaje(mensaje: str, llave_publica_dest: rsa.RSAPublicKey) -> str:
    """
    Cifra un mensaje usando RSA-OAEP + AES-256-GCM.

    Formato de salida (base64):
        <llave_aes_cifrada_b64>:<nonce_b64>:<texto_cifrado_b64>

    Args:
        mensaje: Texto plano a cifrar.
        llave_publica_dest: Llave pública RSA del destinatario.

    Returns:
        String cifrado en base64 listo para transmitir.
    """
    # 1. Llave AES efímera de 256 bits
    llave_aes = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(llave_aes)

    # 2. Cifrar mensaje con AES-256-GCM
    nonce = os.urandom(12)          # 96 bits recomendado para GCM
    texto_cifrado = aesgcm.encrypt(nonce, mensaje.encode("utf-8"), None)

    # 3. Cifrar llave AES con RSA-OAEP
    llave_aes_cifrada = llave_publica_dest.encrypt(
        llave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 4. Empaquetar todo en base64 separado por ":"
    partes = [
        base64.b64encode(llave_aes_cifrada).decode(),
        base64.b64encode(nonce).decode(),
        base64.b64encode(texto_cifrado).decode(),
    ]
    return ":".join(partes)


def descifrar_mensaje(payload: str, llave_privada: rsa.RSAPrivateKey) -> str:
    """
    Descifra un payload producido por `cifrar_mensaje`.

    Args:
        payload: String en formato "<llave_aes_b64>:<nonce_b64>:<cifrado_b64>".
        llave_privada: Llave privada RSA del receptor.

    Returns:
        Texto plano original.

    Raises:
        ValueError: Si el formato es inválido.
        Exception: Si el descifrado falla (mensaje alterado / llave incorrecta).
    """
    partes = payload.split(":")
    if len(partes) != 3:
        raise ValueError("Payload cifrado con formato inválido.")

    llave_aes_cifrada = base64.b64decode(partes[0])
    nonce             = base64.b64decode(partes[1])
    texto_cifrado     = base64.b64decode(partes[2])

    # Descifrar llave AES con RSA-OAEP
    llave_aes = llave_privada.decrypt(
        llave_aes_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Descifrar mensaje con AES-256-GCM (también verifica autenticidad)
    aesgcm = AESGCM(llave_aes)
    return aesgcm.decrypt(nonce, texto_cifrado, None).decode("utf-8")