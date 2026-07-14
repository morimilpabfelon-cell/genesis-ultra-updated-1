# Continuidad, transferencia y recuperación

## Distinción crítica

- **Backup:** copia cifrada; no activa una instancia.
- **Transfer:** movimiento gobernado desde un cuerpo disponible hacia otro.
- **Recovery:** restauración cuando el cuerpo anterior no puede completar la transferencia.

## Modelo inicial: un cuerpo escritor activo

Para evitar bifurcaciones, solo un cuerpo puede tener autoridad de escritura principal en cada momento.

Estados:

- `candidate`
- `active_writer`
- `read_only`
- `suspended`
- `revoked`
- `lost`

## Transferencia normal

### Cuerpo A

1. Audita la cadena.
2. Crea un checkpoint.
3. Registra `transfer.intent`.
4. Congela nuevas escrituras.
5. Construye un paquete cifrado.
6. Autoriza el destino.

### Cuerpo B

1. Verifica protocolo, semilla, identidad, memoria y checkpoint.
2. Verifica la autorización.
3. Recibe un nuevo `body_id`.
4. Registra `transfer.accepted`.
5. Continúa desde el último hash válido.

### Cierre

El cuerpo A registra `transfer.completed` y pasa a `read_only` o `revoked`.

## Recuperación de emergencia

1. Cargar el último backup verificable.
2. Verificar checkpoint y semilla.
3. Obtener aprobación del guardián.
4. Emitir un nuevo `body_id`.
5. Registrar `recovery.restored`.
6. Declarar `complete`, `known_gap` o `fork_risk`.
7. Revocar el cuerpo perdido cuando sea posible.

Una recuperación con eventos ausentes sigue perteneciendo a la misma instancia, pero debe declarar la discontinuidad.

## Prevención de clones activos

Una copia de archivos no obtiene autoridad automáticamente. Se deben detectar dos cuerpos reclamando la misma época de escritura, eventos distintos con la misma secuencia, dos descendientes del mismo hash y cuerpos revocados intentando escribir.
