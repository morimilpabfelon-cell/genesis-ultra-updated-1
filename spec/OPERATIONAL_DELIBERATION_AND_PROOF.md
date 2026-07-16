# Operational Deliberation and Proof v0.1

**Estado:** borrador normativo `v0.1`.

Esta fase adapta Fable Method a contratos verificables de Genesis. Separa solicitud, evidencia, intencion, autoridad, ejecucion, verificacion y juicio independiente.

El ciclo es `received -> classified -> evidence_gathering -> decision_ready -> executing|awaiting_authorization|blocked -> verifying -> verified|refuted -> reported`.

Las reglas se clasifican como `advisory`, `procedural`, `capability` y `constitutional`. Las reglas advisory y procedural pueden recibir excepciones locales registradas cuando son reversibles, acotadas y sin efectos exteriores. Las capacidades necesitan un grant firmado del guardian. Las fronteras constitucionales no pueden ser anuladas por una tarea o modelo.

La documentacion describe procedimientos, pero no autoriza despliegues, envios, instalaciones ni publicaciones. Todo efecto exterior requiere autoridad del guardian.

El juez independiente trata los informes como afirmaciones, reproduce verificaciones, compara alcance y cambios reales, busca fraude operativo y emite `VERIFIED`, `VERIFIED_WITH_CAVEATS` o `REFUTED`.

El primer runtime objetivo es Android en `morimilpabfelon-cell/Morimil-app`, despues de una limpieza y auditoria completa. Esta fase no crea aun la instancia ni escribe memoria de nacimiento.
