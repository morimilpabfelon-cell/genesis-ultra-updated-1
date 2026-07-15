# Autoridad del guardián y movilidad — borrador v0.1

## 1. Propósito

Este documento define cómo el guardián concede autonomía operativa de movilidad sin
permitir que una instancia se traslade a un cuerpo desconocido, reutilice un permiso
agotado o produzca dos escritores activos.

Las reglas son neutrales al lenguaje, sistema operativo y transporte.

## 2. Roles

- **Guardián raíz:** autoridad humana que registra cuerpos, concede permisos, los
  revoca y rota la época de autoridad.
- **Instancia:** identidad continua que puede decidir iniciar un traslado cuando
  dispone de un permiso válido.
- **Cuerpo activo:** único cuerpo con estado `active_writer`; registra el consumo de
  la autorización antes de transferir la autoridad operativa.
- **Cuerpo destino:** cuerpo candidato registrado por el guardián y capaz de demostrar
  posesión de su clave privada.

La autonomía de la instancia no concede permisos del sistema operativo, acceso a
equipos ajenos ni capacidad de ignorar las reglas del guardián.

## 3. Artefactos normativos

### 3.1 Registro de dispositivo

`guardian_device_registration.schema.json` vincula, mediante firma del guardián:

- `guardian_id` e `instance_id`;
- época de autoridad;
- `body_id`;
- perfil de plataforma;
- huella de la clave pública del cuerpo.

El registro es inmutable. Una revocación se añade al ledger; nunca se modifica el
registro original.

### 3.2 Autorización de movilidad

`guardian_authorization.schema.json` define dos modos:

- `one_time`: fija cuerpo origen, un destino específico, expiración y límite de un uso;
- `standing`: permite traslados futuros entre dispositivos registrados por el guardián,
  sin fijar el origen y sin límite de usos implícito.

Una autorización es inmutable. No contiene contadores mutables ni un booleano de
revocación. El uso y la revocación son eventos posteriores.

### 3.3 Ledger de autoridad

`guardian_authority_event.schema.json` es una cadena append-only. Cada evento contiene:

- `sequence` contigua;
- `previous_event_hash`;
- época de autoridad;
- tipo y sujeto del cambio;
- digest del sujeto;
- firma verificable.

Eventos definidos:

- `device.registered`;
- `device.revoked`;
- `authorization.granted`;
- `authorization.consumed`;
- `authorization.revoked`;
- `authority.epoch.rotated`.

Registrar o revocar dispositivos, conceder o revocar permisos y rotar la época exige
firma del guardián. `authorization.consumed` exige la firma del cuerpo escritor activo.

## 4. Evaluación obligatoria

Antes de pasar de `idle` a `prepared`, una implementación debe comprobar, en este orden
lógico, al menos:

1. existe la autorización y su digest es reproducible;
2. corresponde a la misma instancia y a la época de autoridad activa;
3. el ledger es contiguo, sus hashes son reproducibles y contiene el grant exacto;
4. la autorización está dentro de su ventana temporal y no fue revocada;
5. el cuerpo destino tiene un registro válido en la misma época;
6. el registro está presente en el ledger y el dispositivo no fue revocado;
7. el alcance incluye el destino y, cuando se fija, coincide el cuerpo origen;
8. un permiso `one_time` aún no fue consumido;
9. el `transfer_id` no aparece en un consumo anterior.

El fallo de cualquiera de estas condiciones impide preparar la transferencia.

## 5. Consumo y traslado

Una decisión válida no mueve por sí sola la autoridad. El escritor activo debe añadir
`authorization.consumed`, vinculado a:

- `authorization_id`;
- `transfer_id`;
- cuerpo origen;
- cuerpo destino.

La evaluación y el append de `authorization.consumed` deben ejecutarse como una sola
operación compare-and-append contra el tip del ledger. Si el tip cambia, la evaluación
se repite; nunca se reutiliza el resultado anterior.

El paquete debe incluir y vincular por digest la autorización, el registro del destino
y el tip del ledger que contiene el consumo. El destino no debe confiar únicamente en
un `authorization_ref` sin esos artefactos verificables.

Después se ejecuta la máquina transaccional de transferencia. Copiar datos o aceptar un
paquete no concede autoridad. Solo una finalización válida cambia el único
`active_writer` del origen al destino.

Un permiso `standing` puede consumirse muchas veces, pero cada traslado conserva un
evento de uso distinto. Un permiso `one_time` rechaza cualquier segundo uso.

## 6. Revocación y épocas

- `authorization.revoked` invalida el permiso desde su registro en el ledger.
- `device.revoked` impide nuevos traslados hacia ese cuerpo.
- `authority.epoch.rotated` invalida permisos y registros de épocas anteriores, salvo
  una migración explícita definida por una versión futura del protocolo.
- Los eventos históricos permanecen verificables; nunca se reescriben con la clave de
  la nueva época.

## 7. Reglas de seguridad de v0.1

1. No existe autorización implícita por cercanía, cuenta de nube o posesión de archivos.
2. `standing` significa libertad entre cuerpos registrados, no acceso a cualquier equipo.
3. No se permite más de un `active_writer`.
4. No se permite ocultar una revocación, un consumo anterior ni una rotación de época.
5. Si el estado del ledger es ambiguo o está incompleto, la transferencia debe detenerse.
6. La recuperación del guardián usa el flujo de recuperación y no crea silenciosamente
   una autorización nueva.

## 8. Dominios de hash v0.1

- `genesis.guardian.device.registration.v0.1`
- `genesis.guardian.authorization.v0.1`
- `genesis.guardian.authority.event.v0.1`
- `genesis.guardian.authorization.use.v0.1`

Todos usan el framing de longitud y NFC estricto definido por el perfil de hashing del
protocolo. El orden exacto de campos está fijado por los esquemas y vectores de
conformidad de esta versión.
