import json
from datetime import datetime


def crear_mensaje(tipo, contenido, usuario=None):
    """
    Crea un mensaje estructurado en JSON.
    tipos: 'publico', 'privado', 'sistema', 'error'
    """
    return json.dumps({
        "tipo":     tipo,
        "usuario":  usuario,
        "contenido": contenido,
        "hora":     datetime.now().strftime("%H:%M:%S")
    })


def parsear_mensaje(raw):
    """Intenta parsear JSON, si falla devuelve el texto plano."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"tipo": "texto", "contenido": raw}


def formatear_para_mostrar(msg_dict):
    """Convierte el dict a string legible para el usuario."""
    hora     = msg_dict.get("hora", "")
    usuario  = msg_dict.get("usuario", "")
    contenido = msg_dict.get("contenido", "")
    tipo     = msg_dict.get("tipo", "texto")

    if tipo == "sistema":
        return f"[{hora}] *** {contenido}"
    elif tipo == "privado":
        return f"[{hora}] [Privado de {usuario}]: {contenido}"
    elif tipo == "publico":
        return f"[{hora}] {usuario}: {contenido}"
    else:
        return contenido