import logging
import os

# Carpeta donde se van a guardar los logs
CARPETA_LOGS = "logs"


def configurar_logger():
    # Creamos la carpeta de logs si no existe
    if not os.path.exists(CARPETA_LOGS):
        os.makedirs(CARPETA_LOGS)

    # Configuramos el formato de los mensajes del log
    formato = "%(asctime)s - %(levelname)s - %(message)s"

    # Configuramos el logger para que guarde en archivo y muestre en consola
    logging.basicConfig(
        level=logging.INFO,
        format=formato,
        handlers=[
            # Guarda los logs en un archivo
            logging.FileHandler(os.path.join(CARPETA_LOGS, "servidor.log"), encoding="utf-8"),
            # Tambien los muestra en la consola
            logging.StreamHandler()
        ]
    )

    logging.info("Sistema de logs iniciado")
