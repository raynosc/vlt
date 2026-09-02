# Quick Access — Ventana Flotante de Búsqueda Rápida

[English](../quick-access.md) | [Español](quick-access.md)

`vlt-quick` proporciona una ventana compacta de búsqueda en tiempo real para encontrar y copiar valores de secretos al portapapeles de forma instantánea. Está diseñada para vincularse a un atajo global de teclado (ej. `Shift+Cmd+Space`).

## Uso

```bash
# Vía CLI de vlt:
vlt quick

# Binario independiente:
vlt-quick

# Atajo nativo de macOS configurado en vlt-gui:
Shift + Cmd + Space
```

### Códigos de Salida

| Código | Significado |
|--------|-------------|
| 0 | Secreto copiado exitosamente |
| 1 | Cancelado (tecla Esc) |
| 2 | Error |

## Atajos de Teclado

| Tecla | Acción |
|-------|--------|
| Escribir | Buscar secretos (filtrado en vivo) |
| ↑ / ↓ | Navegar resultados |
| Enter | Copiar al portapapeles |
| Esc | Cerrar / cancelar |

## Características de Seguridad

1. **Auto-Limpieza del Portapapeles**: Al copiar, se programa un proceso desacoplado que vacía el portapapeles de forma segura tras 30 segundos.
2. **Sin Fuga en Argumentos**: El secreto viaja al subproceso de borrado a través de `stdin`, protegiéndolo de herramientas como `ps aux`.
3. **Persistencia en Segundo Plano**: Se integra con el Systray de macOS y Windows para abrir y cerrar al instante sin retrasos de inicialización.
