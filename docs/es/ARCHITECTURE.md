# Arquitectura de vlt — Secure Secrets Manager

[English](../ARCHITECTURE.md) | [Español](ARCHITECTURE.md)

`vlt` es un gestor de contraseñas y secretos local-first y zero-knowledge diseñado para todo el mundo (usuarios particulares, equipos y desarrolladores). Almacena contraseñas, inicios de sesión, semillas 2FA/TOTP, claves API, certificados TLS y claves SSH en una bóveda SQLite cifrada, ofreciendo extracción enriquecida de metadatos, auditorías Watchtower, persistencia en la barra de menú y una interfaz gráfica nativa moderna.

## Filosofía de Diseño

1. **Local-First y Resiliencia Offline:** La bóveda es una base de datos SQLite local (`vault.sqlite`). Todas las operaciones críticas (cifrado, descifrado, búsqueda ciega) ocurren de forma estrictamente local. La sincronización es un complemento opcional.
2. **Zero-Knowledge:** Ni el servidor de sincronización ni terceros tienen acceso a las claves de cifrado o secretos en texto plano. El cifrado y descifrado ocurren exclusivamente en el cliente.
3. **Seguridad por Diseño:** Prácticas criptográficas sólidas desde la base: derivación Argon2id, cifrado autenticado AES-256-GCM, verificación en tiempo constante y borrado de portapapeles mediante tuberías stdin seguras.
4. **Modularidad y Binarios Especializados:** Binarios independientes (`vlt`, `vlt-gui`, `vlt-tui`, `vlt-quick`, `vlt-sync`) para cada flujo de trabajo.
5. **Extensibilidad:** Soporte para múltiples tipos de secretos (X.509, SSH, PKCS#12, TOTP) con sobre de metadatos extensible en formato JSON.

## Componentes del Sistema

### 1. `vlt` (CLI)
Núcleo del gestor para operaciones de terminal y automatización de pipelines: `add`, `get`, `edit`, `rm`, `list`, `search`, `import`, `export`, `pki`, `audit`.

### 2. `vlt-gui` (GUI Nativa de Escritorio)
Interfaz gráfica construida con Fyne v2:
* **Diseño en 3 Columnas:** Barra lateral, lista y visor de detalles.
* **Atajos Globales Sin Permisos (macOS):** Atajos de sistema (`Shift+Cmd+Space` y `Shift+Cmd+V`) usando la API Carbon `RegisterEventHotKey` (0 permisos de accesibilidad requeridos).
* **Barra de Menú / Systray:** Icono Retina monocromo que mantiene la aplicación residente en segundo plano.
* **Dashboard Watchtower:** Análisis de contraseñas débiles, duplicadas y certificados por expirar.

### 3. `vlt-tui` (Interfaz de Terminal)
Interfaz interactiva basada en Charm Bubble Tea.

### 4. `vlt-quick` (Popup Flotante)
Buscador emergente ultra-rápido para copiar credenciales sin abrir la ventana completa.

### 5. `vlt-sync` (Servidor de Sincronización)
Servidor auto-alojable con eventos SSE en tiempo real y autenticación mTLS Zero-Trust.

## Modelo de Seguridad

* **Esquema SQLite v7:** Secretos almacenados con índices ciegos HMAC (`name_lookup = HMAC-SHA256(MasterKey, "passwd.name." + Name)`). Cero texto plano en disco.
* **Seguridad del Portapapeles:** Las credenciales se transmiten a procesos secundarios desacoplados mediante `stdin` (nunca en `argv`/`ps aux`) y se limpian condicionalmente tras 30 segundos.
* **Sanitización de Memoria:** Sobrescritura inmediata a cero con `crypto.Zeroize`.

## Estructura del Proyecto

* **`cmd/`:** Puntos de entrada para los binarios.
* **`internal/`:** Lógica de negocio interna (`crypto`, `store`, `secret`, `gui`, `tui`, `sync`, etc.).
* **`docs/`:** Documentación en inglés y `docs/es/` para español.
