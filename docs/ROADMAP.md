# Roadmap de vlt

Este documento describe la visión a largo plazo, las características planificadas y el trabajo pendiente del proyecto. Se prioriza la seguridad, la experiencia de usuario y la portabilidad multiplataforma.

---

## Visión

`vlt` busca ser el gestor de secretos preferido para desarrolladores individuales y equipos pequeños que valoran:

*   **Control total**: datos almacenados localmente, cero dependencia de servicios en la nube de terceros.
*   **Seguridad real**: encriptación zero-knowledge, no "security theater".
*   **Velocidad**: acceso ultra-rápido via CLI, TUI y GUI.
*   **Portabilidad**: funciona igual en macOS, Linux y Windows.

---

## Versiones y Features

### v1.0.0 — Core Vault (Completado ✅)

*   Derivación de claves con Argon2id.
*   Encriptación AES-256-GCM por secreto.
*   CLI completa con todos los comandos base.
*   TUI interactiva.
*   Importación y exportación (CSV, JSON, Bitwarden, KeePass, etc.).
*   Gestión de certificados (X.509, SSH, PKCS#12).

### v1.1.0 — GUI + Biometría (Completado ✅)

*   `vlt-gui` nativo con Fyne.
*   Desbloqueo Touch ID / Face ID (macOS).
*   Quick Access popup (`vlt-quick`).
*   Dashboard Watchtower (contraseñas débiles, duplicados, certificados expirados).
*   Tema oscuro glassmorphism.
*   Multi-vault support.

### v1.2.0 — Sync Server (Completado ✅)

*   Servidor de sincronización auto-hosteable (`vlt-sync`).
*   Sincronización zero-knowledge entre dispositivos.
*   Autenticación por API key.
*   Soporte para Docker + Caddy (TLS automático).
*   Scripts de testing para sincronización.

### v1.3.0 — Seguridad y Hardening Criptográfico (Completado ✅)

Todas las vulnerabilidades identificadas fueron auditadas y resueltas:

#### Tier 1 — Críticos
* ✅ **S-01**: `sync_encryption_key` y `api_key` cifrados con AES-256-GCM y clave maestra.
* ✅ **S-02**: Seed TOTP/HOTP cifrado dentro del envelope de metadatos.
* ✅ **S-06**: Limpieza de portapapeles segura sin pasar secretos en argumentos del proceso.

#### Tier 2 — Altos
* ✅ **S-03**: Nombres y metadatos cifrados (`encrypted_name` + blind index HMAC `name_lookup`).
* ✅ **S-04**: Eliminación de Keychain inseguro; master password explícito y zeroizado en RAM.
* ✅ **S-05**: Sync con resolución LWW y soporte completo de lápidas (*tombstones*).
* ✅ **S-12**: Unlock de GUI optimizado a una única derivación Argon2id.

#### Tier 3 & 4
* ✅ **S-07 & S-08**: Servidor de sync con rate-limiting, límite de payload y mTLS Zero-Trust (`tls.RequireAndVerifyClientCert`).
* ✅ **S-10**: SQLite en modo WAL, `secure_delete = FAST`, permisos `0600`.
* ✅ **S-11**: AES-GCM con Additional Authenticated Data (AAD) para prevenir transposición de blobs.
* ✅ **S-13**: Zeroización inmediata de buffers en memoria RAM con `crypto.Zeroize`.
* ✅ **S-14**: Mnemónico de recuperación conforme a BIP-39 (24 palabras).

### v1.4.0 — Motor OTP / Authenticator y Auditoría (Completado ✅)
* ✅ Implementación RFC 6238 (TOTP) + RFC 4226 (HOTP) en `internal/otp/`.
* ✅ Decodificación de QR codes e importación automática.
* ✅ Visualización en tiempo real de cuentas regresivas en GUI y TUI.
* ✅ Comandos CLI `vlt otp` y soporte en Watchtower.

### v1.5.0 — Zero-Trust mTLS y Multiplataforma (Completado ✅)
* ✅ Generador PKI integrado (`vlt pki generate`, `vlt pki client`) conforme a RFC 5280 y estándares Apple.
* ✅ Soporte nativo para Windows (`make build-windows`, notificaciones Toast).
* ✅ Auto-fallback resiliente en configuraciones multi-bóveda.
* ✅ Sincronización en tiempo real vía SSE con auto-pull y notificaciones de escritorio.

### v1.5.0 — Análisis y Auditoría (Planificado 📋)

| Feature | Descripción | Referencia |
|---------|-------------|------------|
| **Password Strength Analysis** | Análisis profundo de contraseñas con `zxcvbn` | `openspec/changes/extend-check-password-analysis/` |
| **Breach Detection** | Integración con APIs de haveibeenpwned (k-anonymity) | Propuesta |
| **Certificate Chain Validation** | Validación de cadenas de certificados | Propuesta |
| **SSH Known Hosts Analysis** | Detección de claves comprometidas en known_hosts | Propuesta |

### v1.6.0 — UX / Accesibilidad (Planificado 📋)

| Issue | Descripción | Referencia |
|-------|-------------|------------|
| U-01 | Sin indicador de progreso durante unlock | `ISSUES.md` |
| U-02 | `vlt get` imprime a stdout por defecto (invertir a clipboard) | `ISSUES.md` |
| U-03 | Warning de password débil después de confirmación | `ISSUES.md` |
| U-04 | Watchtower sin acciones "Rotate" contextuales | `ISSUES.md` |
| U-05 | Recovery kit solo se muestra una vez | `ISSUES.md` |
| U-06 | Mensaje genérico "decryption failed" | `ISSUES.md` |
| U-07 | GUI sin auto-lock por inactividad | `ISSUES.md` |
| U-08 | README sobre-promete biometría | `ISSUES.md` |

### v2.0.0 — Ecosistema y Mobile (Futuro 🔮)

*   **Mobile app**: App nativa (React Native o Flutter) para iOS/Android con sync server.
*   **CLI Plugin System**: Extensibilidad para comandos personalizados.
*   **Secret Sharing**: Compartir secretos de forma segura (e.g., "este secreto expira en 24h").
*   **Audit Logs**: Registro inmutable de acceso a secretos (local).
*   **Team Vaults**: Modelo multi-usuario con clave compartida (sin servidor centralizado).

---

## Infraestructura y tooling

| Área | Estado | Notas |
|------|--------|-------|
| CI/CD | ✅ | Tests, linting, build multi-plataforma |
| Docker image | ✅ | `Dockerfile` para `vlt-sync` |
| Documentación | 🚧 | En progreso — `ARCHITECTURE.md`, `USER_GUIDE.md`, `CONTRIBUTING.md` |
| OpenSpec SDD | ✅ | Artefactos completos para cambios significativos |
| Cobertura de tests | 🚧 | Alta cobertura en `cli`, `store`, `crypto`; mejorar en `sync` y `gui` |
| Seguridad | 🚧 | Auditoría completada; correcciones pendientes (v1.3.0) |

---

## Cómo leer este roadmap

*   **Completado (✅)**: Funcionalidad lista para producción.
*   **En Progreso (🚧)**: Trabajo activo en esta área.
*   **Planificado (📋)**: Diseñado y priorizado; implementación pendiente.
*   **Futuro (🔮)**: Ideas exploratorias sin fecha estimada.

Los issues de `ISSUES.md` se priorizan en el orden de su编号 (S-01 primero, luego S-02, etc.). Las features en `openspec/` tienen sus propiosartefactos de diseño con tareas detalladas.