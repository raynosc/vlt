# Roadmap y Plan de Arquitectura: Aplicación Móvil (iOS / Android)

Este documento establece el plan técnico, las consideraciones de seguridad y la lista de tareas (TODO) para extender el ecosistema `vlt` hacia dispositivos móviles.

---

## 1. Consideraciones Críticas de Seguridad Móvil

| Área | Riesgo / Requisito | Solución Arquitectónica |
| :--- | :--- | :--- |
| **Criptografía** | Riesgo de desincronización si se reescribe el cifrado. | **Core Compartido en Go**: Compilar `internal/crypto`, `internal/store` y `internal/sync` vía `gomobile` / C-FFI en un binario unificado (`.xcframework` / `.aar`). |
| **Biometría (FaceID / TouchID)** | Evitar pedir la clave maestra en cada uso sin comprometer la seguridad. | **Secure Enclave / Android Keystore**: Tras el primer desbloqueo, derivar una clave secundaria envuelta en hardware con flags `kSecAccessControlBiometryAny`. |
| **Memoria en Reposo** | Fuga de contraseñas cuando la app pasa a segundo plano. | **Zeroize en background**: Limpiar las estructuras de datos en memoria y bloquear la bóveda inmediatamente al entrar en background. |
| **Capturas de Pantalla** | Robo de contraseñas mediante screenshots o grabación de pantalla. | **FLAG_SECURE (Android)** y **Ocultamiento de ventana en `sceneWillResignActive` (iOS)** con pantalla borrosa/placeholder. |
| **Portapapeles** | Contraseñas que permanecen indefinidamente en el clipboard. | **Auto-clear timer**: Limpiar el portapapeles automáticamente a los 30 o 45 segundos de haber copiado un secreto. |

---

## 2. TODO y Plan de Fases

### Fase 1: Onboarding y Emparejamiento por QR
- [ ] **1.1** Implementar comando CLI `vlt sync export-qr` para generar un QR de emparejamiento con el payload de sincronización.
- [ ] **1.2** Agregar botón "Vincular Dispositivo Móvil" en `vlt-gui` que muestre el código QR en pantalla.
- [ ] **1.3** Definir el esquema del payload QR (URL del servidor, `vault_uuid`, `api_key`, `sync_encryption_key`).

### Fase 2: Paquete Puente (Bridge) en Go
- [ ] **2.1** Crear el paquete `pkg/bridge` con interfaz C-compatible / `gomobile` para:
  - `UnlockVault(password string) -> sessionHandle`
  - `SearchSecrets(query string) -> JSON`
  - `GetSecret(id string) -> JSON`
  - `SaveSecret(secretJSON string) -> error`
  - `SyncVault() -> error`
- [ ] **2.2** Automatizar la compilación de `.xcframework` (iOS) y `.aar` (Android) en el `Makefile`.

### Fase 3: Interfaz de la App Móvil
- [ ] **3.1** Diseñar la UI móvil (Lista de secretos, Búsqueda rápida, Detalle de contraseña, Generador OTP).
- [ ] **3.2** Integrar escaneo de códigos QR con la cámara del dispositivo para importación y 2FA/TOTP.
- [ ] **3.3** Implementar el flujo biométrico con bloqueo automático por temporizador de inactividad (1 min, 5 min, inmediato).

### Fase 4: Extensión de Auto-Rellenado (Autofill Provider)
- [ ] **4.1** Implementar `CredentialProviderExtension` en iOS para Safari y apps nativas.
- [ ] **4.2** Implementar `AutofillService` en Android.
- [ ] **4.3** Asegurar que la extensión de Autofill consulte la base de datos local en <50ms mediante índices HMAC ciegos.

### Fase 5: Sincronización en Segundo Plano
- [ ] **5.1** Sincronización automática de cambios al abrir la app o desbloquear con biometría.
- [ ] **5.2** Soporte para background fetch silencioso.
