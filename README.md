# Chat Seguro — Proyecto Final
**Seguridad Informática**

Sistema de chat en tiempo real implementado con sockets TCP en Python, con soporte para múltiples clientes concurrentes, autenticación de usuarios, cifrado asimétrico RSA y registro de eventos en bitácora.

---

## Equipo

| Integrante | Área | Archivos |
|------------|------|----------|
| Jonathan Romero | Backend / Servidor | `server.py`, `protocol.py` |
| Ricardo Cervantes | Seguridad | `auth.py`, `crypto.py` |
| Jesús Portillo | Cliente + Docs | `client.py`, `logger_config.py` |

---

## Estructura del proyecto

```
chat-seguro/
│
├── server/
│   ├── server.py          # Servidor TCP principal
│   ├── auth.py            # Registro y login con bcrypt
│   ├── crypto.py          # Cifrado RSA
│   ├── logger_config.py   # Configuración de logs
│   ├── users.json         # Almacén de usuarios
│   └── logs/              # Bitácora del sistema
│
├── client/
│   ├── client.py          # Cliente TCP con interfaz CLI
│   └── crypto.py          # Generación de llaves RSA
│
├── shared/
│   └── protocol.py        # Formato de mensajes JSON
│
├── docs/
│   ├── ARQUITECTURA.txt
│   ├── ESCENARIOS_CONEXION.md
│   ├── ESTRUCTURA_ARCHIVOS.txt
│   └── ejemplo_uso.md
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

## Tecnologías y librerías

| Tecnología | Uso |
|------------|-----|
| Python 3.12+ | Lenguaje principal |
| `socket` | Comunicación TCP cliente-servidor |
| `threading` | Concurrencia: un hilo por cliente |
| `bcrypt` | Hash seguro de contraseñas |
| `cryptography` | Generación y uso de llaves RSA (OAEP + SHA-256) |
| `logging` | Registro de eventos en archivo |
| `json` | Protocolo de mensajes estructurados |

---

## Mecanismos de seguridad

### Hash de contraseñas con bcrypt
Las contraseñas nunca se almacenan en texto plano. Se usa bcrypt con sal aleatoria, resistente a fuerza bruta y tablas rainbow.

```python
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### Cifrado asimétrico RSA
Cada cliente genera un par de llaves RSA de 2048 bits al iniciar. Los mensajes se cifran con la llave pública del destinatario usando el esquema OAEP + SHA-256.

### Validación de entradas
- Username mínimo 3 caracteres, solo alfanumérico
- Contraseña mínimo 4 caracteres
- Se rechazan mensajes vacíos y comandos inválidos

### Límite de conexiones
El servidor rechaza conexiones cuando hay 5 clientes activos.

---

## Instalación y ejecución

### 1. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 2. Iniciar el servidor

```bash
python server/server.py
```

### 3. Conectar clientes (en terminales separadas)

```bash
python client/client.py
```

---

## Comandos disponibles

| Comando | Descripción |
|---------|-------------|
| `/msg <usuario> <texto>` | Envía un mensaje privado |
| `/ayuda` | Muestra los comandos disponibles |
| `/salir` | Desconecta al cliente |

---

## Documentación adicional

Ver carpeta [`docs/`](docs/):

- [`ARQUITECTURA.txt`](docs/ARQUITECTURA.txt) — Diagramas ASCII de capas del sistema, flujos de autenticación y cifrado
- [`ESCENARIOS_CONEXION.md`](docs/ESCENARIOS_CONEXION.md) — 8 escenarios de conexión con pasos y resultados esperados
- [`ESTRUCTURA_ARCHIVOS.txt`](docs/ESTRUCTURA_ARCHIVOS.txt) — Descripción detallada de cada archivo del proyecto
- [`ejemplo_uso.md`](docs/ejemplo_uso.md) — Guía paso a paso para ejecutar el sistema desde cero

---

## Repositorio

Cada integrante trabajó en su rama correspondiente y se integró a `main` mediante pull requests.

```
main
├── server-dev
├── security-dev
└── client-dev
```
