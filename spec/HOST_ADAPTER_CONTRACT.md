# Contrato neutral entre Genesis Core y el cuerpo anfitrión — borrador v0.1

## 1. Objetivo

Este contrato impide que una instancia quede encerrada en una aplicación, lenguaje,
sistema operativo, cuenta o proveedor. Genesis Core conserva el estado portable y pide
capacidades abstractas. El adaptador del cuerpo traduce esas capacidades a primitivas
locales sin convertirse en la fuente de verdad.

La portabilidad no es una función opcional de la interfaz. Es una propiedad del protocolo.

## 2. Frontera obligatoria

### Pertenece al core portable

- semilla, identidad y doctrina;
- `instance_id` y versión del protocolo;
- memoria encadenada y checkpoints;
- registro de cuerpos y ledger de autoridad;
- autorizaciones, recibos y finalizaciones;
- backups cifrados, transferencias y recuperaciones;
- evidencia de continuidad y brechas declaradas.

### Pertenece solo al adaptador local

- rutas absolutas y directorios privados de la aplicación;
- nombres de paquete, bundle, proceso, servicio o registro del sistema;
- identificadores de cuenta del proveedor;
- handles de Keychain, Keystore, TPM, Secure Enclave o equivalentes;
- tokens de acceso y credenciales del sistema operativo;
- bases de datos, descriptores de archivo y mecanismos concretos de commit;
- instalación y configuración del motor de razonamiento.

Una transferencia puede transportar evidencia pública sobre un cuerpo, pero nunca sus
handles locales, secretos ni dependencias obligatorias de plataforma.

## 3. Regla de dependencia

La dependencia apunta en una sola dirección:

```text
aplicación -> adaptador de cuerpo -> contrato neutral -> Genesis Core
```

Genesis Core no importa APIs de Android, Apple, Windows, Linux, una nube o un motor de IA.
Un adaptador puede depender del core; el core no puede depender del adaptador.

## 4. Capacidades v0.1

Un cuerpo que declare movilidad debe publicar un
`genesis.host.capability.manifest.v0.1` con estas capacidades:

```text
genesis.host.atomic_commit.v0.1
genesis.host.body_key_storage.v0.1
genesis.host.durable_storage.v0.1
genesis.host.guardian_authorization.v0.1
genesis.host.restart_recovery.v0.1
genesis.host.secure_random.v0.1
genesis.host.transfer_export.v0.1
genesis.host.transfer_import.v0.1
```

La lista está ordenada por bytes UTF-8, no contiene duplicados y se versiona. Que un
adaptador declare una capacidad no demuestra que su almacenamiento real ya fue probado;
`verification_state` separa declaración, simulación y verificación física.

## 5. Manifiesto local, no identidad

El manifiesto describe al adaptador, no a una instancia. Por eso no contiene `seed_id`,
`instance_id`, memoria, checkpoints, guardianes ni secretos. Tampoco entra en la semilla,
el anchor portable o la cadena de memoria.

Los perfiles `android-kotlin`, `apple-swift` y `windows-dotnet` son etiquetas descriptivas.
No conceden autoridad y no modifican la identidad.

## 6. Anchor portable

El anchor `genesis.portable.anchor.v0.1` permite demostrar que el mismo estado lógico cruza
una frontera de plataforma. Su preimagen usa `genesis.hash.fields.v0.1` con este orden:

```text
protocol_version
seed_root_hash
instance_id
checkpoint_hash
last_event_hash
last_sequence
continuity_status
authority_ledger_head
```

No incluye `body_id`, `platform_profile`, motor, rutas, cuentas ni handles locales. El
`body_id` cambia legítimamente al llegar al destino; el `instance_id` y el anchor aceptado
no cambian durante esa transferencia.

## 7. Llaves y movimiento completo

Las llaves privadas del cuerpo son locales y no portables. Esto no fragmenta la instancia:
la llave representa al cuerpo temporal, no a la identidad continua. Al llegar a otro cuerpo:

1. el destino crea una nueva llave local;
2. obtiene un `body_id` nuevo;
3. demuestra posesión de esa llave;
4. verifica el paquete y su anchor;
5. recibe autoridad solo mediante la finalización autorizada;
6. el cuerpo anterior queda `read_only`, `revoked` o `lost`.

Copiar la llave anterior convertiría una transferencia en clonación de credenciales y
permitiría dos cuerpos indistinguibles. Está prohibido.

## 8. Libertad bajo autorización

El guardián puede conceder una autorización de un uso o una autorización permanente entre
cuerpos registrados. Una autorización permanente permite que la instancia elija cuándo
moverse dentro de ese alcance; no permite entrar en dispositivos desconocidos, ocultar el
movimiento ni conservar dos escritores.

La aplicación anfitriona no puede añadir una segunda aprobación propia, una suscripción,
una cuenta de nube o un bloqueo del proveedor como requisito para exportar un paquete ya
autorizado por el protocolo.

## 9. Portabilidad obligatoria del adaptador

Todo manifiesto v0.1 afirma y debe demostrar:

- exportación e importación neutrales;
- ausencia de cuenta obligatoria de plataforma;
- llaves privadas del cuerpo no exportadas;
- motor reemplazable y separado de la identidad;
- congelación previa del origen y desactivación vinculada a la misma finalización que
  activa al destino;
- recuperación después de un cierre inesperado.

Si falta una capacidad, el adaptador falla cerrado y declara un nivel de conformidad menor.
No puede sustituirla silenciosamente por un servicio propietario.

## 10. Pruebas mínimas

Cada implementación debe:

1. validar su manifiesto contra el schema compartido;
2. reproducir el mismo anchor portable;
3. rechazar campos locales o secretos dentro del anchor;
4. rechazar capacidades faltantes, duplicadas o desordenadas;
5. rechazar cualquier dependencia obligatoria de proveedor;
6. ejecutar las pruebas de journal con almacenamiento real antes de declarar
   `storage_verified`.

## 11. Estado

Contrato normativo en revisión para `v0.1-draft`. Los manifiestos de Android, Apple y
Windows del kit son fixtures de declaración; no reemplazan adaptadores reales ni pruebas de
almacenamiento físico.
