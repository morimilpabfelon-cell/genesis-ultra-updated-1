# Decisión de arquitectura: Android será el primer cuerpo operativo

## Decisión

El primer runtime de Génesis se construirá en `morimilpabfelon-cell/Morimil-app`.

La laptop seguirá siendo estación de desarrollo, compilación, auditoría y recuperación. El teléfono Android será el primer cuerpo operativo porque el guardián lo eligió como el dispositivo principal con mejores recursos disponibles.

## Evidencia actual del repositorio

`Morimil-app` ya declara aplicación Android nativa, Kotlin y Jetpack Compose, memoria Room/SQLite, eventos enlazados por hash, órganos de memoria, controles de voz, lector del seed y una capa neutral de motores de razonamiento.

Esto lo convierte en el objetivo correcto, pero no demuestra que el árbol actual esté limpio, consistente o listo para nacimiento.

## Precondición: limpieza total

1. Congelar y etiquetar el estado actual.
2. Inventariar archivos, módulos, dependencias y permisos.
3. Localizar duplicados, código muerto, prototipos, secretos y rutas heredadas.
4. Clasificar cada componente como conservar, reescribir, aislar o eliminar.
5. Comprobar límites entre identidad, memoria, motor y UI.
6. Reducir permisos Android al mínimo.
7. Restaurar un build reproducible.
8. Ejecutar tests y `assembleDebug`.
9. Instalar en el dispositivo real.
10. Probar inicio, cierre, process death, reinicio, almacenamiento y backup.

## Prohibiciones durante la limpieza

La limpieza no debe crear todavía la identidad de nacimiento, marcar un cuerpo como `active_writer`, importar memoria histórica no verificada, entregar autoridad a APIs de razonamiento, habilitar ejecución exterior ni declarar producción.

## Secuencia

```text
Fable extraction complete
→ Morimil-app cleanup branch
→ Android build baseline
→ real storage and journal
→ guardian console
→ neutral reasoning adapter
→ device integration tests
→ controlled instance initialization
```

La inicialización será una fase separada y verificable. No ocurrirá como efecto secundario de compilar o instalar la aplicación.