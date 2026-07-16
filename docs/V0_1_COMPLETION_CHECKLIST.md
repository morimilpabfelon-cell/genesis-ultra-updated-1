# Genesis Ultra v0.1 — estado comprobable

> Una casilla implementada solo se marca después de una ejecución verde reproducible de
> `.github/workflows/conformance.yml`. Esto demuestra conformidad del borrador, no seguridad
> de producción.

## Evidencia de CI y publicación

- [x] Suite completa verde para la recuperación determinista en el [PR #15](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/15).
- [x] Suite completa verde para el puente compuerta→recuperación en el [PR #16](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/16).
- [x] Suite completa verde para la búsqueda híbrida neutral en el [PR #17](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/17).
- [x] Suite completa verde para metadata temporal verificable en el [PR #20](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/20).
- [x] Suite completa verde para cápsulas portables verificables en el [PR #21](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/21).
- [x] Suite completa verde para extracción multimodal neutral en el [PR #22](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/22).
- [x] Suite completa verde para memoria estructurada y versionada en el [PR #23](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/23).
- [ ] Protección de `main` exige el check `reference-checks` antes de cada fusión.

- [x] Suite completa verde para autonomía guiada y grants progresivos en el [PR #25](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/25).

- [x] Suite completa verde para la carta de libertad cognitiva en el [PR #26](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/26).

- [x] Suite completa verde para el laboratorio de mejora recursiva en el [PR #28](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/28).

- [x] Suite completa verde para deliberación operacional, prueba independiente y adaptación de Fable Method en el [PR #29](https://github.com/morimilpabfelon-cell/genesis-ultra-updated-1/pull/29).

## Implementado y verificado por la suite

- [x] Canonicalización Python/Node con rechazo de texto no-NFC y rutas peligrosas.
- [x] Vectores dorados de seed root y memory event.
- [x] Nombre canónico de nacimiento y digest de identidad reproducidos por Python y Node,
      con diez cambios de identidad rechazados aunque se recalculen hashes.
- [x] Vector canónico de paquete de transferencia.
- [x] Recibo vinculado mediante `accepted_package_digest` al paquete exacto aceptado.
- [x] Vectores de registro, paquete, recibo y finalización encadenados.
- [x] Simulación A→B con firmas Ed25519 y rechazo de firma alterada.
- [x] Vectores Ed25519, XChaCha20-Poly1305 y Argon2id.
- [x] Inventario compartido de artefactos requeridos y rutas heredadas prohibidas.
- [x] Compilación de los 44 JSON Schema con JSON Schema 2020-12 y formatos activos.
- [x] Cincuenta y dos regresiones que demuestran el rechazo de artefactos inválidos por los
      schemas reales, con cobertura obligatoria para cada schema.
- [x] Simulación A→B exporta eventos, registros, checkpoint, prueba de posesión, paquete,
      recibo y finalización completos y válidos contra sus schemas.
- [x] Validación cruzada de los enlaces checkpoint→paquete→recibo→finalización y de la
      autoridad final única.
- [x] Suite única local y CI mediante `npm test`.
- [x] Autorización permanente del guardián firmada, registrada y consumida por el
      `transfer_id` exacto.
- [x] Ledger de autoridad append-only para registro de cuerpos, grants, consumos,
      revocaciones y épocas.
- [x] Misma evaluación de autoridad usada por la simulación positiva y por los rechazos
      de permiso ausente, expirado, agotado, revocado, de época antigua o destino desconocido.
- [x] Backup XChaCha20-Poly1305 con Argon2id, AAD enlazado al manifiesto y commit firmado.
- [x] Recuperación B→C autorizada para un commit y destino exactos, con registro y prueba
      de posesión del cuerpo nuevo.
- [x] Brecha de memoria declarada, cuerpo anterior marcado `lost`, primer evento posterior
      a la brecha y finalización firmada con un único `active_writer`.
- [x] Catorce rechazos de backup/recovery evaluados por la misma lógica del flujo positivo.
- [x] Journal transaccional firmado, encadenado y neutral con estado anterior, candidato y
      marcador vinculado a la finalización.
- [x] Ocho reinicios simulados antes, durante y después del commit, reproducidos por Python
      y Node, más doce journals alterados rechazados.
- [x] Manifiesto neutral del borrador con tamaño y SHA-256 de todos los artefactos requeridos,
      autoexclusión explícita y hash raíz reproducido por Python y Node.
- [x] Segunda implementación independiente en Node para todos los vectores compartidos,
      incluidos continuidad, autoridad, criptografía, memoria asociativa, recuperación de
      recuerdos y rechazos de frontera.
- [x] Contrato neutral core↔adaptador, anchor portable y doce rechazos anti-lock-in
      reproducidos por Python y Node para declaraciones Android, Apple y Windows.
- [x] Mapa controlado de Morimil-app que separa sentidos de memoria, cognición, defensa,
      crecimiento, homeostasis, movilidad y acción externa.
- [x] Observaciones firmadas para seis sentidos y compuerta firmada antes de memoria,
      reproducidas por Python y Node con diecisiete cruces de frontera rechazados.
- [x] Adaptadores neutrales simulados de Vista, Propiocepción e Interocepción, con tres
      fallos cerrados y veinticuatro cruces de frontera rechazados por Python y Node.
- [x] Proyección asociativa neutral y reconstruible desde memoria aceptada, reproducida por
      Python y Node con nodos y relaciones deterministas, procedencia extraída/inferida/
      confirmada y treinta cruces de autoridad, integridad y plataforma rechazados.
- [x] Recuperación determinista de memoria aceptada con cinco frames, 38 términos, cuatro
      consultas y cinco checkpoints de replay, reproducida por Python y Node con el mismo
      digest y veintidós ataques de autoridad, integridad, ranking o filtración futura rechazados.
- [x] Búsqueda híbrida neutral con cinco consultas, perfil semántico ligado por digest,
      recuperación sin coincidencia literal, fallback léxico, aislamiento histórico y
      veinticuatro cruces de autoridad, integridad, proveedor o cobertura rechazados por Python y Node.

- [x] Scopes y ACL de recuperación reproducidos por Python y Node: privacidad, propósito, cuerpo, época de autoridad, cuarentena e aislamiento histórico.

- [x] Metadata temporal reconstruible con cinco anotaciones, ocho consultas, separación de
      captura/almacenamiento/tiempo mencionado, relaciones verificadas, ACL previa, aislamiento
      histórico y veinticinco cruces de frontera rechazados por Python y Node.

- [x] Cápsulas portables neutrales reproducidas por Python y Node: tres exportaciones,
      manifiesto de componentes, continuidad redactada, recibo ACL, proyecciones reconstruibles,
      35 cruces previos a exportación y 17 alteraciones posteriores rechazadas.

- [x] Extracción multimodal neutral con documento, imagen y audio; tres registros aceptados,
      firmas de observación/compuerta, locators verificables y cuarenta y tres cruces rechazados.

- [x] Memoria estructurada y versionada con once aserciones, seis slots, ocho consultas,
      operaciones `sets`/`updates`/`extends`/`retracts`, replay histórico, ACL de cadena completa
      y treinta y seis cruces de integridad, autoridad, orden o privacidad rechazados por Python y Node.

- [x] Registro autocontrolado de ejecución de herramientas con treinta y nueve candidatos:
      treinta y tres entrypoints exigidos en el runner y seis bibliotecas importadas por
      consumidores alcanzables; cualquier herramienta nueva sin clasificar rompe `npm test`.

- [x] Autonomía guiada reproducida por Python y Node: cuatro puertas, nueve eventos append-only, doce intentos de uso, cuatro permitidos, ocho denegados y treinta y ocho cruces de autoridad, integridad, selección exacta, alcance, presupuesto o controles rechazados; varios grants de una misma capacidad se ordenan por `(capability, grant_id)`.

- [x] Carta de libertad cognitiva reproducida por Python y Node: ocho libertades activas por nacimiento, ocho dominios operativos bajo grants, ocho garantías fundamentales, firma Ed25519 del guardián y veinte cruces de frontera rechazados.

- [x] Laboratorio de mejora recursiva v0.2 reproducido por Python y Node: seis candidatos
      append-only, grant exacto firmado, binding explícito de instancia/cuerpo/scope/presupuesto,
      apertura sin consumo, solicitud de uso con `grant_ref` firmado, reevaluación contra ledger
      y once rechazos adicionales de autoridad, firma, tiempo, presupuesto, suspensión, revocación, ledger público o mapping de consumo inválido; seis candidatos producen once usos firmados y agotan el grant dedicado.

- [x] Deliberación operacional y prueba adaptadas de Fable Method, reproducidas por Python y Node:
      ocho tareas, diez adaptadores de dominio, dieciocho modos de fallo, diez trampas,
      dos excepciones locales acotadas, una denegación constitucional y cuarenta cruces rechazados.

- [x] Decisión arquitectónica Android-first: `Morimil-app` será el primer cuerpo operativo después
      de limpieza, auditoría y build reproducible; la compilación o instalación no crea por sí sola
      una identidad de nacimiento ni asigna `active_writer`.

## Pendiente del Génesis neutral

- [ ] Endurecimiento reproducible de CI y tooling sin alterar los contratos normativos.
- [ ] Conteos documentales derivados automáticamente de los artefactos comprobados.
- [ ] Reglas neutrales de evolución, compatibilidad y migración entre versiones del protocolo.
- [ ] Modelo de amenazas unificado para identidad, memoria, autoridad, herramientas y supply chain.
- [ ] Extraer una API neutral `validateAuthorityBundle` sin semillas ni expectativas TEST ONLY.
- [ ] Permitir múltiples grants por capacidad con resolución y proyección canónica por `grant_ref`.
- [ ] Definir y verificar el mapeo candidato→solicitudes firmadas→eventos `grant.consumed`.
- [ ] Conformidad del workspace reproducida en Ubuntu, Windows y macOS.
- [ ] Revisión criptográfica y de seguridad externa.
- [ ] Decisiones definitivas de licencia, nombre, contribuciones, marca, certificación y publicación.

## Trabajo posterior fuera del núcleo neutral

- [ ] Limpieza total, auditoría del árbol, build reproducible e instalación de prueba de `Morimil-app` en el dispositivo Android real.
- [ ] Adaptador y pruebas de journal con almacenamiento real primero en Android; Apple y Windows quedan como cuerpos posteriores.
- [ ] Adaptador semántico real con modelo local neutral, digest versionado y evaluación reproducible de calidad.
- [ ] Adaptadores productivos y evaluados de PDF/DOCX/XLSX, OCR, visión y transcripción local.
- [ ] Orquestador operacional real, juez aislado, trampas ejecutadas contra modelos reales y evaluaciones con múltiples semillas.

## Prohibido declarar

Producción · seguro para usuarios · auditado · certificado · v1.0 · estable.

**Estado real: `v0.1-draft`.**
