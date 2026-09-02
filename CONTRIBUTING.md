# Guía de Contribución a vlt

¡Gracias por tu interés en contribuir a `vlt`! Valoramos todas las contribuciones, desde la corrección de errores tipográficos hasta nuevas características y mejoras de arquitectura. Esta guía te ayudará a empezar.

## ¿Cómo Contribuir?

Aquí hay algunas maneras de contribuir:

*   **Informar Errores:** Si encuentras un error, por favor abre un _issue_ en nuestro [repositorio GitHub](https://github.com/raynosc/vlt/issues).
*   **Sugerir Características:** Si tienes una idea para una nueva característica o mejora, abre un _issue_ para discutirla.
*   **Escribir Código:** Envía Pull Requests para corregir errores, implementar nuevas características o mejorar el código existente.
*   **Mejorar la Documentación:** Ayúdanos a mantener la documentación clara, completa y actualizada.

## Configuración de tu Entorno de Desarrollo

Para empezar a desarrollar con `vlt`, necesitarás:

1.  **Go (versión 1.26+):** Instala Go siguiendo las instrucciones oficiales en [go.dev/doc/install](https://go.dev/doc/install).
2.  **Git:** Para clonar el repositorio y gestionar tus cambios.
3.  **Make:** Para usar los comandos de construcción y prueba definidos en el `Makefile`.

### Clonar el Repositorio

```bash
git clone https://github.com/raynosc/vlt.git
cd vlt
```

### Dependencias Go

`vlt` utiliza módulos de Go. Las dependencias se resolverán automáticamente cuando ejecutes comandos `go build` o `go test`. Si necesitas descargar las dependencias explícitamente, puedes usar:

```bash
go mod tidy
```

## Construyendo el Proyecto

El proyecto utiliza un `Makefile` para simplificar la construcción. Puedes construir todos los binarios para tu plataforma actual con:

```bash
make build
```

Para construir binarios multiplataforma (ej. macOS arm64 y amd64):

```bash
make build-all
```

Para ver todos los objetivos de `make` disponibles:

```bash
make help
```

## Ejecutando Pruebas

Es crucial que todas las pruebas pasen antes de enviar un Pull Request. `vlt` tiene una cobertura de pruebas significativa.

*   **Ejecutar todas las pruebas unitarias:**
    ```bash
    make test
    ```

*   **Ejecutar todas las pruebas con el detector de carreras (race detector):**
    ```bash
    make test-all
    ```

*   **Generar informe de cobertura de código (HTML):**
    ```bash
    make test-cover
    ```

## Estilo de Código y Linting

Adherirse a un estilo de código consistente ayuda a mantener el proyecto legible y mantenible. Utilizamos las herramientas estándar de Go:

*   **Formato:** `go fmt` se usa para formatear el código. Se ejecuta automáticamente en el objetivo `lint`.
*   **Linting:** `go vet` se usa para encontrar errores potenciales. Se ejecuta automáticamente en el objetivo `lint`.

Para ejecutar todas las comprobaciones de estilo y linting:

```bash
make lint
```

## Guía de Mensajes de Commit

`vlt` sigue la especificación de [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Esto facilita la generación automática de changelogs y el seguimiento del historial del proyecto.

### Formato Básico

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

*   **`type` (obligatorio):** `feat` (nueva característica), `fix` (corrección de error), `docs` (cambios en la documentación), `style` (formato, puntos y comas), `refactor` (refactorización sin cambio de característica ni corrección de error), `perf` (cambio de rendimiento), `test` (agregar pruebas faltantes), `build` (cambios en el sistema de compilación), `ci` (cambios en la configuración de CI), `chore` (otros cambios que no modifican el código fuente ni las pruebas).
*   **`scope` (opcional):** El área del código que afecta el cambio (ej. `cli`, `gui`, `sync`, `keychain`, `store`).
*   **`description` (obligatorio):** Un resumen conciso del cambio en tiempo presente.

**Ejemplos:**

*   `feat(gui): Añadir soporte para desbloqueo Touch ID`
*   `fix(cli): Corregir error de importación de CSV`
*   `docs(architecture): Mejorar sección de flujo de datos`

## Proceso de Pull Request (PR)

1.  **Crea una _issue_:** Antes de comenzar un trabajo significativo, por favor crea una _issue_ para discutir la característica o el error. Esto evita el trabajo duplicado y asegura que tu contribución esté alineada con la dirección del proyecto.
2.  **Crea una rama:** Crea una rama nueva a partir de `main` para tu trabajo:
    ```bash
    git checkout main
    git pull origin main
    git checkout -b feature/mi-nueva-caracteristica
    ```
3.  **Realiza tus cambios:** Escribe el código, las pruebas y actualiza la documentación según sea necesario.
4.  **Haz commits:** Utiliza los [mensajes de commit convencionales](#guía-de-mensajes-de-commit).
5.  **Ejecuta pruebas y linting:** Asegúrate de que `make test` y `make lint` pasen antes de enviar tu PR.
6.  **Envía tu PR:** Abre un Pull Request a la rama `main` de este repositorio.
    *   Incluye una descripción clara del cambio.
    *   Haz referencia a la _issue_ relevante (ej. `Fixes #123`, `Closes #456`).
    *   Si tu PR es parte de un cambio más grande documentado en `openspec`, por favor menciona los artefactos relevantes (`proposal.md`, `spec.md`, etc.).
7.  **Revisión:** Tu PR será revisado por los mantenedores del proyecto. Espera comentarios y prepárate para realizar cambios si es necesario.

## Trabajando con `openspec` (Especificación y Diseño)

Para cambios más grandes o arquitectónicos, `vlt` utiliza un proceso de Especificación y Diseño Dirigido por el Agente (SDD/OpenSpec). Los artefactos relevantes se almacenan en el directorio `openspec/`.

Si estás trabajando en una característica significativa, es posible que se te pida que contribuyas a este proceso, o al menos que revises los artefactos existentes para entender la justificación y el diseño detrás de un cambio.

Gracias de nuevo por tu contribución. ¡Esperamos tus Pull Requests!
