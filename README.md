# 🔐 Hybrid Crypto (Rust)

Sistema modular de cifrado híbrido implementado en Rust (edición 2024). Combina la flexibilidad del intercambio asimétrico de claves mediante curvas elípticas (**X25519**) con el rendimiento y autenticación del cifrado simétrico autenticado (**AES-256-GCM**), integrando además almacenamiento seguro de claves privadas en el gestor de credenciales del sistema operativo (**Keyring / Keychain**).

---

## 📋 Tabla de Contenidos

- [Características Principales](#-características-principales)
- [Arquitectura Criptográfica](#-arquitectura-criptográfica)
  - [Estructura del Sobre Digital (`envelope.bin`)](#-estructura-del-sobre-digital-envelopebin)
  - [Flujo de Cifrado y Descifrado](#-flujo-de-cifrado-y-descifrado)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Requisitos Previos](#-requisitos-previos)
- [Guía de Uso](#-guía-de-uso)
  - [1. Flujo Seguro con Keyring del S.O. (Recomendado)](#1-flujo-seguro-con-keyring-del-so-recomendado)
  - [2. Flujo Básico en Disco](#2-flujo-básico-en-disco)
  - [3. Limpieza de Credenciales y Artefactos](#3-limpieza-de-credenciales-y-artefactos)
- [Consideraciones de Seguridad](#-consideraciones-de-seguridad)
- [Dependencias](#-dependencias)
- [Licencia](#-licencia)

---

## ✨ Características Principales

- **Cifrado Híbrido Moderno**: Utiliza Diffie-Hellman sobre Curve25519 (X25519) para acordar un secreto compartido, y AES-256-GCM para cifrar el contenido.
- **Claves Efímeras (PFS parcial)**: El remitente genera un par de claves efímero por cada mensaje, asegurando que el secreto compartido y la clave AES sean únicos para cada sobre.
- **Cifrado Autenticado (AEAD)**: AES-256-GCM garantiza confidencialidad e integridad; cualquier alteración en el sobre digital o en el texto cifrado es detectada de inmediato.
- **Resguardo Seguro de Claves**: Soporte para almacenar la clave privada en el gestor nativo de credenciales del S.O. (Linux Secret Service / GNOME Keyring / KWallet, macOS Keychain, Windows Credential Manager).
- **Sobre Digital Autónomo**: Todo lo necesario para descifrar el mensaje (excepto la clave privada del receptor) viaja empaquetado en un solo formato binario compacto.

---

## 🧠 Arquitectura Criptográfica

### Estructura del Sobre Digital (`envelope.bin`)

El sobre digital empaqueta de forma contigua los elementos indispensables para reconstruir el secreto compartido y descifrar la carga útil:

```text
+-----------------------------+--------------------+---------------------------------------+
| Clave Pública Efímera       | Nonce (IV)         | Texto Cifrado + Tag de Autenticación  |
| 32 bytes                    | 12 bytes           | N bytes                               |
| (Sender Ephemeral Public)   | (AES-GCM Nonce)    | (AES-256-GCM Ciphertext + 16B MAC)    |
+-----------------------------+--------------------+---------------------------------------+
0                             32                   44                                    44 + N
```

### Flujo de Cifrado y Descifrado

```text
[Remitente]                                               [Destinatario]
    |                                                           |
    |-- 1. Genera par efímero (sk_e, pk_e)                      |
    |-- 2. Diffie-Hellman(sk_e, pk_destinatario)                |
    |      => shared_secret (32 bytes)                          |
    |-- 3. Deriva clave AES-256 a partir del secreto            |
    |-- 4. Genera Nonce aleatorio (12 bytes con OsRng)          |
    |-- 5. Cifra mensaje: AES-256-GCM(shared_key, nonce, texto)  |
    |-- 6. Empaqueta [pk_e (32B) + nonce (12B) + ciphertext]    |
    |                                                           |
    |==================== Sobre Digital =======================>|
    |                                                           |
    |                                  7. Extrae pk_e y nonce --|
    |                                  8. Obtiene sk_destinatario
    |                                     (del Keyring o disco)-|
    |                                  9. Diffie-Hellman(sk_dest, pk_e)
    |                                     => shared_secret      |
    |                                 10. Descifra y valida tag |
    |                                     con AES-256-GCM       |
    v                                                           v
```

---

## 📁 Estructura del Proyecto

```text
hybrid_crypto/
├── Cargo.toml            # Definición de dependencias y configuración del paquete
├── .gitignore            # Exclusión de binarios compilados y artefactos (.bin)
├── README.md             # Documentación del proyecto
└── src/
    ├── main.rs           # Implementación base con persistencia de claves en disco
    └── bin/
        ├── keychain.rs   # Implementación segura con Keyring del sistema operativo
        └── cleankey.rs   # Utilidad para revocar claves del Keyring y limpiar archivos
```

- **`src/main.rs`** (`hybrid_crypto`): Flujo demostrativo donde las claves `public_key.bin` y `private_key.bin` se guardan directamente en el sistema de archivos local.
- **`src/bin/keychain.rs`** (`keychain`): Variante de nivel de producción que almacena la clave privada en el gestor de credenciales del S.O. bajo el servicio `hybrid_crypto_rust` y usuario `recipient_private_key`.
- **`src/bin/cleankey.rs`** (`cleankey`): Herramienta de mantenimiento para eliminar la clave almacenada en el Keyring y remover `public_key.bin` y `envelope.bin`.

---

## 🛠 Requisitos Previos

1. **Rust y Cargo**: Cadena de herramientas de Rust actualizada (soporta edición 2024).
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
2. **Dependencias del Sistema para Keyring (solo en Linux sin entorno de escritorio completo)**:
   La crate `keyring` en Linux utiliza D-Bus y la especificación Secret Service (GNOME Keyring, KWallet). Si compilas en entornos mínimos o servidores headless, asegúrate de contar con:
   ```bash
   sudo apt update && sudo apt install -y libdbus-1-dev pkg-config
   ```

---

## 🚀 Guía de Uso

### 1. Flujo Seguro con Keyring del S.O. (Recomendado)

Ejecuta el binario `keychain`:

```bash
cargo run --bin keychain
```

**Comportamiento:**
1. Comprueba si existe la clave privada en el Keyring del sistema y la pública en `public_key.bin`.
2. Si no existen, genera un nuevo par X25519, guarda la clave privada en el almacén seguro del S.O. y escribe la pública en `public_key.bin`.
3. Cifra un mensaje de demostración y genera el sobre digital `envelope.bin`.
4. Lee el sobre, solicita la clave privada al Keyring del sistema operativo y descifra el mensaje.

---

### 2. Flujo Básico en Disco

Para pruebas rápidas de laboratorio donde las claves residen como archivos binarios locales:

```bash
cargo run --bin hybrid_crypto
# o simplemente:
cargo run
```

**Archivos generados:**
- `private_key.bin`: Clave privada X25519 (32 bytes).
- `public_key.bin`: Clave pública X25519 (32 bytes).
- `envelope.bin`: Sobre digital cifrado.

---

### 3. Limpieza de Credenciales y Artefactos

Para reiniciar el estado, revocar la clave privada del Keyring y eliminar archivos `.bin` temporales:

```bash
cargo run --bin cleankey
```

Salida esperada:
```text
[-] Llave privada eliminada exitosamente del Keyring del S.O.
[-] Archivo 'public_key.bin' eliminado localmente.
[-] Archivo 'envelope.bin' de prueba eliminado.
```

---

## 🔒 Consideraciones de Seguridad

- **Protección de la Clave Privada**: Guardar claves privadas en archivos en texto plano (`private_key.bin`) es vulnerable a filtraciones accidentales o malware sin privilegios elevados. Por ello, el enfoque basado en `keychain.rs` delega la protección al subsistema criptográfico del sistema operativo.
- **Exclusión en Git**: Los archivos generados (`*.bin`) están explícitamente ignorados en `.gitignore` para evitar filtraciones de claves y artefactos al repositorio.
- **Generación Criptográficamente Segura**: Todo material aleatorio (claves y nonces) se obtiene mediante `rand::rngs::OsRng`, recurriendo a fuentes de entropía del kernel (`/dev/urandom` / `getrandom`).
- **Resistencia a Modificaciones**: Al utilizar el modo AEAD de AES-256-GCM, si un adversario modifica un solo bit del sobre digital (cabecera, nonce o contenido cifrado), el descifrado fallará de inmediato sin procesar datos adulterados.

---

## 📦 Dependencias

| Crate | Versión | Propósito |
|---|---|---|
| [`x25519-dalek`](https://crates.io/crates/x25519-dalek) | `2.0` | Criptografía asimétrica Diffie-Hellman sobre Curve25519 |
| [`aes-gcm`](https://crates.io/crates/aes-gcm) | `0.10` | Cifrado simétrico autenticado (AES-256-GCM) |
| [`rand`](https://crates.io/crates/rand) | `0.8` | Generador de números aleatorios criptográficamente seguro (`OsRng`) |
| [`keyring`](https://crates.io/crates/keyring) | `2.0` | Integración multiplataforma con el almacén seguro de credenciales |
| [`hex`](https://crates.io/crates/hex) | `0.4` | Codificación/decodificación hexadecimal para resguardo en Keyring |
| [`serde`](https://crates.io/crates/serde) / [`serde_json`](https://crates.io/crates/serde_json) | `1.0` | Serialización y manejo de estructuras de datos |

---

## 📄 Licencia

Este proyecto es de código abierto bajo la licencia MIT o Apache-2.0. Consulta los archivos correspondientes para más información.
