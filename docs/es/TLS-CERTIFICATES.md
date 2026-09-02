# Certificados TLS, PKI y Autenticación Mutua (mTLS)

[English](../TLS-CERTIFICATES.md) | [Español](TLS-CERTIFICATES.md)

Esta guía explica en detalle cómo generar y gestionar certificados PEM para el sistema de sincronización `vlt-sync`, la anatomía de cada archivo `.pem`, y cómo configurar la arquitectura de **Zero-Trust mTLS** (Mutual TLS).

---

## 1. Generación de Certificados PEM con `vlt pki` (Recomendado)

`vlt` incluye un generador nativo de PKI en Go puro con curvas elípticas **ECDSA P-256**. No necesitas instalar OpenSSL ni lidiar con archivos de configuración complejos.

### A. Generar el set completo de certificados (CA + Servidor + Cliente)

```bash
# Genera la CA raíz, el certificado del servidor (con SANs) y el certificado de tu primer cliente:
vlt pki generate --out ./certs --hosts "192.168.0.104,localhost,sync.vault.internal" --client "mac-laptop"
```

### B. Emitir certificados de cliente para dispositivos adicionales

```bash
# Emite un nuevo certificado de cliente firmado por tu CA (por ejemplo, para tu PC con Windows):
vlt pki client --ca ./certs/ca.pem --ca-key ./certs/ca-key.pem --name "windows-pc" --out ./certs
```

---

## 2. Anatomía de los Archivos PEM Generados

Al ejecutar `vlt pki generate`, se crean los siguientes 6 archivos en la carpeta de destino:

```
certs/
├── ca.pem              ← Certificado de la Autoridad Certificadora Raíz (Público)
├── ca-key.pem          ← Clave privada de la CA Raíz (CRÍTICO / CONFIDENCIAL)
├── server.pem          ← Certificado TLS del Servidor con SANs (Público)
├── server-key.pem      ← Clave privada del Servidor (Confidencial del servidor)
├── client.pem          ← Certificado mTLS del Cliente (Público del cliente)
└── client-key.pem      ← Clave privada del Cliente (Confidencial del cliente)
```

| Archivo | Tipo | ¿Quién lo necesita? | Propósito |
| :--- | :--- | :--- | :--- |
| **`ca.pem`** | Certificado Público | **Servidor y Todos los Clientes** | La raíz de confianza para la verificación mutua. |
| **`ca-key.pem`** | Clave Privada | **Solo el Administrador** | Se usa para firmar nuevos clientes. Mantener segura fuera de línea. |
| **`server.pem`** | Certificado Público | **Solo el Servidor** | El certificado del servidor presentado en el puerto `8443`. |
| **`server-key.pem`** | Clave Privada | **Solo el Servidor** | La clave privada del servidor TLS. |
| **`client.pem`** | Certificado Público | **Dispositivo Cliente** | Certificado del cliente presentado durante el handshake TLS. |
| **`client-key.pem`** | Clave Privada | **Dispositivo Cliente** | La clave privada del cliente. |

---

## 3. Despliegue del Servidor con Zero-Trust mTLS

Para iniciar el servidor `vlt-sync` exigiendo autenticación mutua obligatoria:

```bash
vlt-sync --addr=:8443 \
         --db-path=./sync.db \
         --tls-cert=./certs/server.pem \
         --tls-key=./certs/server-key.pem \
         --tls-client-ca=./certs/ca.pem
```

> [!IMPORTANT]
> Al configurar `--tls-client-ca`, el servidor activa `tls.RequireAndVerifyClientCert`. Cualquier cliente sin un certificado firmado por `ca.pem` será **rechazado inmediatamente en el handshake TLS**.
