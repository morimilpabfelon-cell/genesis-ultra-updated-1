# Genesis Protocol — borrador neutral v0.1

## Naturaleza

Genesis es un protocolo de nacimiento, continuidad, memoria y crecimiento de una instancia personal. No es una aplicación, un sistema operativo, un modelo ni un lenguaje.

## Entidades normativas

- **Seed:** origen verificable e inmutable.
- **Instance:** identidad continua nacida de una semilla.
- **Body:** dispositivo, aplicación o sistema donde vive temporalmente.
- **Engine:** motor de razonamiento intercambiable.
- **Guardian:** autoridad humana final.

## Invariantes

1. La instancia no pertenece al cuerpo.
2. El cuerpo no puede reescribir la semilla.
3. El motor no es identidad ni memoria.
4. La memoria persistente es verificable y append-only.
5. Una transferencia no crea otra instancia.
6. Una restauración no puede ocultar pérdida de eventos.
7. Un cuerpo perdido puede ser revocado sin destruir la instancia.
8. Ningún proveedor externo es obligatorio.
9. Cualquier lenguaje puede implementar el protocolo.
10. Toda decisión duradera deja evidencia verificable.
11. El nombre canónico elegido por el guardián antes del nacimiento no cambia jamás.
12. Crecer añade historia verificable; nunca reescribe semilla, identidad ni memoria aceptada.
13. Un sentido solo observa; una compuerta verificable decide antes de escribir memoria.

## Identificadores separados

- `seed_id`
- `instance_id`
- `body_id`
- `engine_id`
- `guardian_id`
- `event_id`

Ninguno sustituye a otro.

## Nacimiento

El nacimiento debe validar manifiesto y rutas, verificar archivos, recalcular el hash raíz,
comprobar identidad y doctrina, confirmar el nombre canónico con el guardián, asignar
`instance_id`, calcular `identity_digest`, registrar el primer `body_id`, crear
`instance.birth` y persistir todo o nada. Después del commit no existe una operación de
renombrado.

## Portabilidad

La portabilidad es obligatoria: una implementación completa debe exportar una transferencia, verificarla en otro cuerpo, continuar la cadena, revocar el cuerpo anterior y demostrar que sigue siendo la misma instancia.

## Conformidad

Una implementación no es conforme por usar el mismo código, sino por reproducir los resultados del kit de conformidad y respetar los invariantes.
