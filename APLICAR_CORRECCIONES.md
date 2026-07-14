# Correcciones de coherencia v0.1 — resumen y cómo subirlas

Se corrigieron los **11 errores objetivos** de la auditoría, en el orden indicado.
Todo verificado ejecutando, no declarado.

## Qué se corrigió

1. **Canonicalización Python/Node unificada** — Node ahora RECHAZA texto no-NFC (antes
   lo normalizaba en silencio). Además se descubrió y cerró otra divergencia: Node pasaba
   números crudos donde Python pasa strings.
2. **Validación de rutas unificada** — Node ahora rechaza NUL y letras de unidad (`C:`),
   igual que Python. Paridad byte a byte.
3. **`continuity_vectors.json` encadenado real** — la finalización referencia el digest
   VERDADERO del recibo (`sha256:d1c184…`), no el ficticio `cccc…`.
4. **Fingerprints cumplen el schema** — `pkfp:` ahora de 16+ caracteres (antes 13).
5. **Firmas ed25519 verificadas de verdad** — la simulación crea la firma, la VERIFICA
   criptográficamente con la clave pública, y prueba que una firma alterada se rechaza.
6. **La simulación FALLA sin PyNaCl** (exit 1) — antes daba falso positivo con exit 0.
7. **REQUIRED unificado** — ambos validadores leen `conformance/required_artifacts.json`
   (50 artefactos), fuente única. Antes exigían listas distintas y omitían archivos.
8. **Checklist a una sola fuente de estado** — sin contradicción arriba/abajo.
9. **Vectores criptográficos reales** — ed25519 + XChaCha20-Poly1305 + Argon2id con casos
   de corrupción, verificados por `validate_crypto_vectors.py`.
10. **Negativos** — las 13 simulaciones ejecutan la detección; la de firma ahora es
    verificación real con rechazo de manipulación.
11. **Un solo workflow** — `draft-conformance.yml` y `validate.yml` eliminados.

## Nuevos archivos
- `conformance/behavior_cases.json` — casos que TODA implementación debe rechazar
  (la cura del error delicado: ya no pueden aceptar datos distintos).
- `conformance/required_artifacts.json` — lista única de artefactos requeridos.

## El error más delicado: RESUELTO
Se probó caso por caso que Python y Node ahora **aceptan y rechazan exactamente lo
mismo**: 0 discrepancias en los 10 casos de comportamiento. Ya puedes añadir Sensorium
u otros módulos sobre una base coherente.

## Subir a main (PowerShell)

```powershell
cd $HOME\Documents
git clone https://github.com/morimilpabfelon-cell/genesis-ultra-updated.git
cd genesis-ultra-updated
# copia el contenido de esta carpeta descomprimida ENCIMA:
Copy-Item "C:\ruta\a\genesis-ultra-updated\*" -Destination . -Recurse -Force

# probar TODO localmente (Python 3.12+, Node 20+, PyNaCl):
pip install pynacl
python tools/validate_workspace.py
node   tools/validate_workspace.mjs
python tools/validate_continuity.py
python tools/validate_crypto_vectors.py
python tools/simulate_transfer.py
python tools/simulate_negatives.py

git add -A
git commit -m "Coherencia v0.1: canonicalizacion unificada, firmas verificadas, vectores cripto reales, workflow unico"
git push origin main
```
Luego revisa la pestaña **Actions** y confirma el workflow único en verde.
