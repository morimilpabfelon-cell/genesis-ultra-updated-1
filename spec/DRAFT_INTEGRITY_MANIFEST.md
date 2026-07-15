# Manifiesto de integridad del borrador v0.1

**Estado:** borrador normativo. No constituye una firma de release ni una certificación.

Este perfil permite comprobar que un árbol de Genesis Ultra contiene exactamente los
artefactos declarados y que sus bytes no cambiaron. No depende de Git, GitHub, un sistema
operativo ni un lenguaje de programación.

## 1. Fuentes y alcance

- El inventario vive en `conformance/required_artifacts.json`.
- El manifiesto vive en `conformance/draft_manifest.json`.
- Cada ruta de `required` debe aparecer exactamente una vez, excepto la ruta del propio
  manifiesto.
- Ninguna ruta de `forbidden` puede existir ni aparecer en el manifiesto.

El archivo del manifiesto se excluye de su propia lista porque ningún archivo finito puede
contener de forma estable el hash criptográfico de todos sus bytes, incluido ese mismo hash.
La exclusión es única, explícita y comprobada mediante `manifest_path` y `self_excluded`.

## 2. Registro de archivo

Cada registro contiene:

```text
path        ruta relativa segura, en NFC y con `/`
size_bytes  longitud exacta del archivo en bytes
digest      "sha256:" + lowercase_hex(SHA-256(file_bytes))
```

Los archivos se ordenan por los bytes UTF-8 de `path`, interpretados sin signo. No se
normalizan saltos de línea, JSON, Markdown ni código antes de calcular el digest.

## 3. Hash raíz

Dominio:

```text
genesis.draft.integrity.root.v0.1
```

La preimagen usa `FRAME` de `HASH_PROFILE_DRAFT.md` en este orden:

```text
FRAME(domain)
FRAME(schema_version)
FRAME(protocol_version)
FRAME(root_hash_profile)
FRAME(file_digest_algorithm)
FRAME(inventory_path)
FRAME(manifest_path)
FRAME(self_excluded)
FRAME(file_count)
```

Después, por cada registro ya ordenado:

```text
FRAME(path)
FRAME(size_bytes)
FRAME(digest)
```

Resultado:

```text
root_digest = "sha256:" + lowercase_hex(SHA-256(preimage))
```

`self_excluded` se representa exactamente como `true` y los enteros en decimal ASCII.

## 4. Rechazo obligatorio

Una implementación debe rechazar el manifiesto si:

- el JSON no cumple `schemas/draft_manifest.schema.json`;
- falta o sobra una ruta respecto del inventario, descontando solo `manifest_path`;
- una ruta está repetida, es insegura, no está en NFC o no respeta el orden canónico;
- una ruta prohibida existe o aparece listada;
- `file_count`, `size_bytes`, un digest de archivo o `root_digest` no coincide;
- se declara otra política de autoexclusión, algoritmo o perfil.

## 5. Actualización

Todo cambio legítimo de archivos debe actualizar primero el inventario cuando corresponda y
después regenerar el manifiesto. La CI debe fallar si el árbol y el manifiesto divergen.

Este mecanismo prueba integridad reproducible del borrador. La autenticidad requiere además
una firma o un commit confiable fuera de este perfil.
