# Ejemplos de Uso — Chat Seguro

Guía paso a paso para ejecutar el sistema desde cero.

---

## Requisitos previos

- Python 3.12 o superior instalado
- Terminal / símbolo del sistema
- Librerías instaladas:

```bash
pip install -r requirements.txt
```

---

## Paso 1 — Iniciar el servidor

Abre una terminal y ejecuta:

```bash
python server/server.py
```

Salida esperada en consola y en `server/logs/servidor.log`:

```
2025-05-17 20:00:01 [INFO] Servidor escuchando en 127.0.0.1:5555
Servidor iniciado en 127.0.0.1:5555
```

El servidor queda en espera. **No cierres esta terminal.**

---

## Paso 2 — Conectar el primer cliente (registro)

Abre una **segunda terminal** y ejecuta:

```bash
python client/client.py
```

Verás el menú de autenticación:

```
=== Chat Seguro ===
1. Iniciar sesión
2. Registrarse
Elige una opción (1/2): 2
Usuario: juan
Contraseña: mipass123
```

Si el registro es exitoso:

```
✓ Registro exitoso

--- Comandos disponibles ---
  /msg <usuario> <texto>   Mensaje privado
  /ayuda                   Ver esta ayuda
  /salir                   Desconectarse
----------------------------
>>
```

---

## Paso 3 — Conectar el segundo cliente (login)

Abre una **tercera terminal**:

```bash
python client/client.py
```

```
=== Chat Seguro ===
1. Iniciar sesión
2. Registrarse
Elige una opción (1/2): 2
Usuario: maria
Contraseña: pass456
✓ Registro exitoso
>>
```

En la terminal de `juan` aparecerá automáticamente:

```
[20:03:45] [Servidor] maria se unió al chat.
```

---

## Paso 4 — Enviar mensajes públicos

Desde la terminal de `juan`:

```
>> hola a todos!
```

En la terminal de `maria` aparece:

```
[20:04:12] juan: hola a todos!
```

Desde `maria`:

```
>> qué onda juan, todo bien?
```

En `juan`:

```
[20:04:25] maria: qué onda juan, todo bien?
```

---

## Paso 5 — Enviar mensaje privado

Desde `juan`:

```
>> /msg maria oye, esto es privado
```

Solo `maria` recibe:

```
[20:05:01] [Privado de juan]: oye, esto es privado
```

Los demás clientes conectados **no ven este mensaje**.

---

## Paso 6 — Intentar mensaje a usuario inexistente

```
>> /msg pedro hola
```

Solo `juan` ve:

```
ERROR:Usuario 'pedro' no encontrado
```

---

## Paso 7 — Ver el archivo de log

Mientras el servidor corre, puedes abrir `server/logs/servidor.log`:

```
2025-05-17 20:00:01 [INFO]    Servidor escuchando en 127.0.0.1:5555
2025-05-17 20:02:10 [INFO]    Conexión exitosa: juan desde ('127.0.0.1', 52100)
2025-05-17 20:03:44 [INFO]    Conexión exitosa: maria desde ('127.0.0.1', 52105)
2025-05-17 20:04:12 [INFO]    Mensaje público de juan
2025-05-17 20:04:25 [INFO]    Mensaje público de maria
2025-05-17 20:05:01 [INFO]    Privado: juan -> maria
```

---

## Paso 8 — Verificar passwords hasheadas

Abre `server/users.json` con cualquier editor de texto:

```json
{
  "juan": {
    "password": "$2b$12$eW5Q8k3mN1xPvLqRtYuIoe7J2HgFdSaKlMnBcVzXwA9..."
  },
  "maria": {
    "password": "$2b$12$rT4mK9pLqNxWvBsYuJoIe3H8FgEcRaZlMnDcVzXwB5..."
  }
}
```

Las contraseñas nunca aparecen en texto plano.

---

## Paso 9 — Probar límite de 5 usuarios

Abre 6 terminales e intenta conectar 6 clientes. El sexto verá:

```
✗ Servidor lleno (max 5)
```

Y se desconectará automáticamente.

---

## Paso 10 — Desconectarse

Desde cualquier cliente:

```
>> /salir
Desconectando...
```

Los demás clientes ven:

```
[20:10:33] [Servidor] juan se desconectó.
```

---

## Errores comunes y soluciones

| Error | Causa probable | Solución |
|-------|----------------|----------|
| `ConnectionRefusedError` | El servidor no está corriendo | Ejecuta `server.py` primero |
| `ModuleNotFoundError: bcrypt` | Librerías no instaladas | `pip install -r requirements.txt` |
| `ERROR:Usuario inválido` | Username con caracteres especiales o muy corto | Usa solo letras y números, mínimo 3 caracteres |
| `ERROR:El usuario ya existe` | Intentas registrar un username repetido | Elige otro nombre de usuario o usa login |
| Puerto 5555 en uso | Otra instancia del servidor corriendo | Cierra el proceso anterior o cambia `PORT` en `server.py` |
