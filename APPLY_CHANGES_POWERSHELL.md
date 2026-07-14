# Cómo subir estos cambios a Genesis-ultra (Windows / PowerShell)

Estos son los archivos nuevos y modificados de la auditoría v0.1. Súbelos a `main`.

## Opción A — copiar sobre tu clon y hacer push (recomendada)

```powershell
# 1. Clona el repo si no lo tienes (o entra al que ya tengas)
cd $HOME\Documents
git clone https://github.com/morimilpabfelon-cell/Genesis-ultra.git
cd Genesis-ultra

# 2. Copia el contenido de esta carpeta descomprimida ENCIMA del repo
#    (ajusta la ruta a donde descomprimiste genesis-ultra-updated)
Copy-Item -Path "C:\ruta\a\genesis-ultra-updated\*" -Destination . -Recurse -Force

# 3. Revisa qué cambió
git status

# 4. Prueba localmente ANTES de subir (necesitas Python 3.12+ y Node 20+)
pip install pynacl
python tools/validate_workspace.py
node   tools/validate_workspace.mjs
python tools/validate_continuity.py
python tools/validate_crypto_vectors.py
python tools/simulate_transfer.py
python tools/simulate_negatives.py

# 5. Si todo pasa, sube a main
git add -A
git commit -m "Auditoria v0.1: simulacion A->B, negativos, fusion de specs duplicados, workflow completo"
git push origin main
```

## Archivos NUEVOS de esta sesión
- `tools/simulate_transfer.py` — simulación completa A→B con firmas ed25519 reales
- `tools/simulate_negatives.py` — 13 simulaciones negativas (ataques rechazados)
- `docs/ARCHITECTURE_DECISIONS.md` — decisiones de arquitectura + diagrama completo
- `reference/README.md` — plan de implementaciones por lenguaje
- `APPLY_CHANGES_POWERSHELL.md` — este archivo

## Archivos MODIFICADOS
- `tools/validate_workspace.py` — alineado al nombre canónico `HASH_PROFILE_DRAFT.md`
- `spec/HASHING_PROFILE_DRAFT.md` — ahora redirige a `HASH_PROFILE_DRAFT.md` (consolidado)
- `spec/GUARDIAN_RECOVERY.md` — ahora redirige a `GUARDIAN_RECOVERY_AND_SIGNATURES.md`
- `.github/workflows/conformance.yml` — ejecuta las 6 comprobaciones (antes 3)
- `docs/V0_1_COMPLETION_CHECKLIST.md` — estado real de la auditoría
- `.gitignore` — entradas de pycache/node_modules

## Verificar el workflow en GitHub tras el push
1. Ve a la pestaña **Actions** del repo.
2. Abre el run más reciente de "Genesis Ultra Conformance".
3. Confirma que los 6 pasos aparecen en verde. Si alguno falla, mándame el log — no
   asumas que pasó sin verlo.
