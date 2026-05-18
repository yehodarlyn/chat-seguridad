# ESCENARIOS DE CONEXIÓN — Chat Seguro

Documento que describe los escenarios posibles de conexión y el comportamiento esperado del sistema en cada caso.

---

## Escenario 1 — Conexión exitosa y chat normal

**Precondición:** servidor corriendo, menos de 5 clientes conectados.

**Pasos:**
1. Cliente ejecuta `python client/client.py`
2. Servidor responde `CMD:AUTH`
3. Cliente elige login o registro e ingresa credenciales
4. Servidor valida y responde `OK:Login exitoso`
5. Cliente entra al loop de mensajes
6. Servidor notifica al resto: `[Servidor] usuario se unió al chat.`

**Resultado esperado:** cliente conectado, puede enviar y recibir mensajes.

---

## Escenario 2 — Credenciales incorrectas

**Precondición:** usuario intenta login con contraseña equivocada.

**Pasos:**
1. Cliente envía `{ "accion": "login", "usuario": "juan", "password": "wrongpass" }`
2. Servidor llama `bcrypt.checkpw()` → retorna `False`
3. Servidor responde `ERROR:Contraseña incorrecta`
4. Conexión se cierra

**Resultado esperado:** acceso denegado, log de advertencia generado.

```
2025-05-17 20:14:03 [WARNING] Auth fallida [login] usuario='juan' desde ('127.0.0.1', 52210)
```

---

## Escenario 3 — Registro de usuario duplicado

**Precondición:** usuario `maria` ya existe en `users.json`.

**Pasos:**
1. Nuevo cliente intenta registrarse con username `maria`
2. Servidor carga `users.json` y encuentra que `maria` ya existe
3. Servidor responde `ERROR:El usuario ya existe`
4. Conexión se cierra

**Resultado esperado:** registro rechazado, `users.json` no se modifica.

---

## Escenario 4 — Servidor lleno (6to cliente)

**Precondición:** 5 clientes ya están conectados y autenticados.

**Pasos:**
1. Cliente 6 se conecta
2. Servidor recibe la conexión e inicia flujo de auth
3. Después de autenticación exitosa, el servidor verifica `len(clientes) >= MAX_CLIENTES`
4. Servidor responde `ERROR:Servidor lleno (max 5)`
5. Conexión se cierra

**Resultado esperado:** cliente 6 rechazado, los 5 anteriores siguen sin interrupciones.

---

## Escenario 5 — Mensaje privado exitoso

**Precondición:** `juan` y `maria` están conectados.

**Pasos:**
1. `juan` escribe: `/msg maria hola, cómo estás?`
2. Servidor parsea el comando, identifica `maria` en `clientes{}`
3. Servidor envía solo a `maria`: `[Privado de juan]: hola, cómo estás?`
4. El resto de clientes no recibe el mensaje

**Resultado esperado:** mensaje entregado solo a `maria`.

---

## Escenario 6 — Mensaje privado a usuario inexistente

**Precondición:** `pedro` no está conectado.

**Pasos:**
1. `juan` escribe: `/msg pedro hola`
2. Servidor busca `pedro` en `clientes{}` → no lo encuentra
3. Servidor devuelve a `juan`: `ERROR:Usuario 'pedro' no encontrado`

**Resultado esperado:** `juan` recibe notificación de error, nadie más es afectado.

---

## Escenario 7 — Desconexión inesperada de cliente

**Precondición:** cliente conectado pierde conexión (cierra terminal, corte de red).

**Pasos:**
1. El hilo del cliente intenta `conn.recv()` → retorna `b''` (conexión cerrada)
2. El hilo sale del loop
3. Bloque `finally` elimina al cliente de `clientes{}`
4. Servidor hace broadcast: `[Servidor] usuario se desconectó.`

**Resultado esperado:** sistema se recupera solo, los demás clientes son notificados.

---

## Escenario 8 — Validación de formato de usuario

**Precondición:** cliente intenta registrarse con username inválido.

| Caso | Input | Resultado |
|------|-------|-----------|
| Username muy corto | `ab` | `ERROR:Usuario inválido` |
| Caracteres especiales | `juan@123` | `ERROR:Usuario inválido` |
| Contraseña muy corta | `123` | `ERROR:Contraseña muy corta` |
| Username vacío | `` | `ERROR:Usuario inválido` |

---

## Resumen de códigos de respuesta del servidor

| Código | Significado |
|--------|-------------|
| `CMD:AUTH` | Solicitud de autenticación |
| `OK:<mensaje>` | Operación exitosa |
| `ERROR:<detalle>` | Error con descripción |
| `[Servidor] <msg>` | Notificación del sistema |
| `[Privado de X]:` | Mensaje privado recibido |
