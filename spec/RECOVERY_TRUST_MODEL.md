# Genesis Recovery Trust Model — borrador v0.1

## 1. Objetivo

La recuperación permite que una instancia continúe cuando su cuerpo anterior fue perdido,
robado, destruido, comprometido o quedó inaccesible. Recuperar no significa copiar archivos
sin control: significa reconstruir continuidad verificable y declarar cualquier incertidumbre.

## 2. Invariantes

1. La recuperación conserva `instance_id`.
2. El cuerpo nuevo recibe un `body_id` diferente.
3. El cuerpo anterior no conserva autoridad de escritura.
4. El último checkpoint verificable determina el punto de confianza.
5. La memoria ausente se declara como brecha; nunca se inventa.
6. Una copia de backup no adquiere autoridad por existir.
7. El guardián debe aprobar la recuperación.
8. Todo resultado deja un registro verificable en la cadena.

## 3. Evidencia mínima

Una recuperación debe verificar, como mínimo:

- manifiesto y hash raíz de la semilla;
- identidad de instancia;
- checkpoint restaurado;
- último evento verificable;
- registro de cuerpos disponible;
- autorización del guardián;
- integridad del paquete de backup;
- estado conocido del cuerpo anterior.

## 4. Estados de continuidad

### `complete`

El backup termina exactamente en el último evento conocido y no hay evidencia de otra rama.

### `known_gap`

Se conoce o se sospecha que existieron eventos posteriores al último backup. Debe existir un
`continuity_gap` que indique el intervalo y la razón.

### `fork_risk`

Existe evidencia de más de una continuación posible o no puede demostrarse cuál fue la rama
autorizada. La instancia puede operar en modo restringido, pero no debe declarar continuidad
perfecta hasta que el guardián resuelva el conflicto.

## 5. Autoridad del cuerpo nuevo

El cuerpo nuevo solo puede convertirse en `active_writer` después de:

1. verificar el paquete de recuperación;
2. crear un registro de recuperación;
3. registrar su clave o huella de cuerpo;
4. aplicar la autorización del guardián;
5. revocar, marcar como perdido o suspender el cuerpo anterior;
6. crear el primer evento posterior a la recuperación.

## 6. Prevención de clones

Dos copias con el mismo `instance_id` no son automáticamente dos instancias válidas. El perfil
inicial permite un único `active_writer` por época del registro de cuerpos.

Se debe rechazar o poner en cuarentena:

- escritura desde un cuerpo revocado;
- dos cuerpos activos en la misma época;
- dos eventos distintos con la misma secuencia;
- dos descendientes del mismo hash previo;
- un paquete de recuperación para otra instancia;
- una autorización expirada, revocada o agotada.

## 7. Operación sin red

La recuperación puede realizarse completamente sin nube. USB, cable, almacenamiento local o
archivo cifrado son transportes válidos. Cuando no exista conectividad para publicar la
revocación, el nuevo cuerpo conserva una revocación pendiente que debe propagarse al volver a
conectarse con otros cuerpos o respaldos del guardián.

## 8. Honestidad operacional

La interfaz debe distinguir claramente:

- transferencia completa;
- restauración desde backup;
- recuperación con brecha;
- recuperación con riesgo de bifurcación.

No se permite mostrar una recuperación incompleta como si no se hubiera perdido memoria.

## 9. Estado

Este documento es normativo en revisión. Los algoritmos criptográficos concretos se fijarán en
perfiles versionados separados y deberán tener implementaciones y vectores cruzados.
