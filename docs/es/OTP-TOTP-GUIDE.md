# Guía Completa de Autenticación de Doble Factor (2FA) y TOTP en `vlt`

[English](../OTP-TOTP-GUIDE.md) | [Español](OTP-TOTP-GUIDE.md)

Esta guía está diseñada para que cualquier persona, independientemente de sus conocimientos técnicos previos, comprenda **qué es TOTP**, **cómo funciona**, **cuáles son sus ventajas de seguridad** y **cómo utilizarlo en `vlt`**.

---

## 1. ¿Qué es 2FA, OTP y TOTP?

### A. 2FA (Two-Factor Authentication / Doble Factor de Autenticación)
Es un método de seguridad que exige **dos pruebas de identidad distintas** antes de concederte acceso a una cuenta:
1. **Primer factor (Algo que sabes)**: Tu nombre de usuario y tu contraseña habitual.
2. **Segundo factor (Algo que tienes)**: Tu gestor de claves `vlt` o una aplicación de autenticación que genera un código temporal.

### B. TOTP (Time-based One-Time Password / RFC 6238)
Es el estándar de la industria adoptado por Google, GitHub, Amazon, Microsoft, etc. Genera un nuevo código cada **30 segundos** combinando:
* Una **clave secreta compartida** (Semilla o *Secret Seed*).
* La **hora actual** del reloj (Unix Timestamp).

```
   ┌────────────────────────────────┐
   │ Clave Secreta (Base32)         │
   │ Ej: JBSWY3DPEHPK3PXP           │
   └───────────────┬────────────────┘
                   │
                   ├────────► [ Algoritmo HMAC-SHA1 ] ──► Código 6 Dígitos: "482 910"
                   │                                      (Válido por 30 segundos)
   ┌───────────────┴────────────────┐
   │ Hora Actual (en bloques de 30s)│
   └────────────────────────────────┘
```

> [!NOTE]
> **No requiere conexión a Internet**: El código se calcula matemáticamente en tu máquina local.

---

## 2. ¿Cuáles son las ventajas de usar TOTP frente a SMS?

| Característica | Códigos por SMS | TOTP en `vlt` (RFC 6238) |
| :--- | :--- | :--- |
| **Seguridad** | ❌ Vulnerable a ataques de *SIM Swapping* (clonación de chip celular) e interceptación de red móvil. | ✅ Inmune a ataques de red móvil. La semilla se almacena cifrada con AES-256-GCM client-side. |
| **Disponibilidad** | ❌ Requiere cobertura celular y señal activa. Fallas al viajar al extranjero. | ✅ Funciona 100% offline, en modo avión o sin conexión celular. |
| **Privacidad** | ❌ El operador telefónico puede registrar la metadata del mensaje. | ✅ Zero-Knowledge. Nadie conoce tus semillas excepto tú. |

---

## 3. Uso en `vlt`

### Añadir un secreto TOTP desde CLI
```bash
# Añadir semilla TOTP
vlt add github-work --type totp --otp-secret "JBSWY3DPEHPK3PXP"

# O usando una URL otpauth:// de un código QR
vlt add aws-root --type totp --otp-url "otpauth://totp/AWS:admin?secret=JBSWY3DPEHPK3PXP&issuer=Amazon"
```

### Generación de Códigos
```bash
# Obtener el código actual de 6 dígitos
vlt otp github-work
```
