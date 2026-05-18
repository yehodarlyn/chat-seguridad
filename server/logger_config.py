import logging
import os

LOG_DIR = "server/logs"


def configurar_logger():
    os.makedirs(LOG_DIR, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(f"{LOG_DIR}/servidor.log", encoding="utf-8"),
            logging.StreamHandler()  # también imprime en consola
        ]
    )
