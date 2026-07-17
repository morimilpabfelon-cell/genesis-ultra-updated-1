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

1. Cargar un backup con `backup_commit` firmado y estado `committed`.
2. Verificar ciphertext, manifiesto, cifrado, checkpoint, semilla e identidad.
3. Registrar el nuevo `body_id` y comprobar posesión de su clave.
4. Verificar la política comprometida al nacer y obtener una autorización exacta por
   `guardian_assisted` o por umbral `policy_fallback` tras su espera.
5. Restaurar sin conceder todavía autoridad de escritura.
6. Declarar `complete`, `known_gap` o `fork_risk`.
7. Marcar el cuerpo anterior como `lost` o `revoked`.
8. Registrar `recovery.restored` y hacer que el destino firme la finalización.
9. Cambiar el registro a un único `active_writer` como parte de la finalización atómica.

Una recuperación con eventos ausentes sigue perteneciendo a la misma instancia, pero debe declarar la discontinuidad.
El procedimiento normativo completo está en `BACKUP_AND_RECOVERY_TRANSACTIONS.md`.

## Prevención de clones activos

Una copia de archivos no obtiene autoridad automáticamente. Se deben detectar dos cuerpos reclamando la misma época de escritura, eventos distintos con la misma secuencia, dos descendientes del mismo hash y cuerpos revocados intentando escribir.
