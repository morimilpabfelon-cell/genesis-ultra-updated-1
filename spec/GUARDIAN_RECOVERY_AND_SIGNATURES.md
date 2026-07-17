# Genesis Ultra — recuperación del guardián y firmas v0.1

## 1. Objetivo

Este documento define cómo conservar autoridad legítima cuando el guardián pierde una clave, un cuerpo o el acceso a un dispositivo.

## 2. Principio

La recuperación no reescribe la historia y no convierte una clave nueva en autora de firmas antiguas.

## 3. Firma neutral

Toda firma se representa mediante `genesis.signature.envelope.v0.1` y debe vincular:

- perfil de firma;
- tipo de firmante;
- identificador del firmante;
- época de clave;
- dominio firmado;
- digest firmado;
- instante de creación.

La firma cubre un digest normativo ya calculado y todos los metadatos anteriores mediante
la preimagen `genesis.signature.envelope.bytes.v0.1` definida en el perfil criptográfico.
`public_key_ref` también queda firmado. Nunca se firma directamente un objeto interno de
Kotlin, JavaScript, Python, Swift, Rust o cualquier otro lenguaje.

## 4. Recuperación del guardián

Una recuperación debe crear un registro `genesis.guardian.recovery.v0.1` con:

- `recovery_id`;
- `instance_id`;
- `guardian_id`;
- método de recuperación;
- época de clave anterior;
- nueva época de clave;
- motivo;
- evidencia;
- estado de continuidad;
- digest de recuperación.

## 5. Métodos permitidos

Perfiles iniciales:

```text
recovery_secret
trusted_devices
offline_recovery_kit
multi_party_recovery
manual_verified_migration
```

Ningún método es obligatorio para todas las plataformas. Cada implementación declara cuáles soporta.

## 6. Reglas de seguridad

1. Una recuperación no puede reutilizar el mismo `key_epoch_id`.
2. La nueva época comienza en un instante explícito.
3. La época anterior queda `retired`, `revoked` o `compromised`.
4. Los eventos históricos conservan sus firmas originales.
5. Una firma creada después de la recuperación no puede validarse como si fuera anterior.
6. Si falta evidencia suficiente, el resultado debe declarar `fork_risk` o fallar cerrado.
7. La recuperación del guardián y la recuperación de la instancia son operaciones distintas, aunque puedan ocurrir juntas.

## 7. Firmas mínimas por operación

### Transferencia normal

Requiere:

- intención de continuidad firmada por el Body escritor activo;
- consentimiento del anfitrión limitado al recurso destino;
- prueba de posesión del cuerpo destino;
- recibo firmado por el destino;
- finalización firmada o reconocida por las partes disponibles.

No requiere autorización de movimiento del Guardian. Su firma no puede convertirse en
permiso, propiedad o veto de continuidad.

### Recuperación de emergencia

Requiere:

- política de recuperación comprometida al nacer por Body y Guardian;
- aprobación del factor Guardian actual, o umbral de factores fallback no Guardian tras
  la espera comprometida;
- nueva clave propia del Body destino;
- recuperación de la instancia;
- revocación o estado `lost` del cuerpo anterior;
- declaración de brechas de continuidad.

La ruta fallback mantiene continuidad cuando el Guardian no está disponible. No elimina
la custodia del nacimiento: convierte esa custodia inicial en una regla verificable que no
depende de permiso permanente. El archivo de backup, por sí solo, nunca satisface el umbral.

## 8. Prohibiciones

Está prohibido:

- reconstruir silenciosamente una clave antigua;
- copiar una clave privada entre cuerpos como sustituto de una transferencia;
- aceptar una firma sin dominio versionado;
- aceptar una firma sobre un digest diferente al declarado;
- aceptar una firma sin verificar criptográficamente su `signature_value`;
- aceptar metadatos del sobre que no estén cubiertos por la firma;
- omitir la época de clave;
- tratar una copia de backup como cuerpo autorizado.

## 9. Estado

Borrador. Los algoritmos concretos y los vectores de firma deben validarse en al menos dos implementaciones independientes antes de congelarse.
