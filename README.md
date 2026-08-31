# its_4_s3cr3_t

Una caja extensible de pequeñas herramientas personales ejecutadas desde Python.
La primera herramienta cifra y descifra palabras o frases con una contraseña que
solo tú conoces.

## Inicio rápido

Requiere Python 3.10 o superior.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python run.py
```

En Linux o macOS, la activación del entorno es:

```bash
source .venv/bin/activate
```

También puedes invocar directamente cada operación:

```powershell
python run.py encrypt
python run.py decrypt
python run.py list
```

La aplicación pide la frase y la contraseña de forma interactiva. El resultado
del cifrado es un texto portable con prefijo `S4S1.` que puedes guardar donde
prefieras. Para recuperarlo necesitas tanto ese texto como la misma contraseña.

## Diseño de seguridad

El contenedor `S4S1` es propio de este proyecto, pero la criptografía no se
reinventa:

- `scrypt` deriva una clave desde tu contraseña usando una sal aleatoria.
- `AES-256-GCM` cifra el contenido y comprueba que nadie lo haya modificado.
- Cada cifrado usa sal y nonce nuevos, por lo que la misma frase produce
  resultados distintos.
- La contraseña nunca se guarda dentro del resultado ni en el repositorio.

No existe recuperación de contraseña. Haz copias del texto cifrado y conserva
la contraseña en un lugar separado. Para datos de alto riesgo o uso compartido,
prefiere un gestor de contraseñas auditado.

## Añadir herramientas

El lanzador vive en `secret_tools/cli.py` y el catálogo en
`secret_tools/registry.py`. Cada nueva utilidad puede registrarse con una clave,
nombre, descripción y función ejecutora, sin mezclar su lógica con las demás.

## Pruebas

```powershell
python -m unittest discover -s tests -v
```

