# its_4_s3cr3_t

Caja defensiva y extensible de pequeñas herramientas personales de
ciberseguridad. Todo se ejecuta localmente desde Python y las funciones que
reciben secretos no los envían por internet.

## Una sola entrada: `run.py`

Ejecuta únicamente:

```powershell
python run.py
```

El menú contiene todas las herramientas y siempre regresa al inicio al terminar
o cancelar una operación:

1. **Proteger texto:** comprime y cifra en `S4S2` en un solo paso.
2. **Recuperar texto:** detecta y abre `S4S1`, `S4S2` o `CZ1`; no necesitas
   elegir entre descifrar y expandir.
3. **Compactar sin contraseña:** crea `CZ1` cuando solo importa reducir longitud.
4. Generar y evaluar contraseñas.
5. Crear secretos o generar códigos TOTP/2FA.
6. Calcular y verificar hashes SHA-256, SHA-512 y BLAKE2b.
7. Buscar credenciales expuestas sin mostrar su valor.
8. Analizar señales sospechosas de una URL sin visitarla.

## Ejecutable para Windows

La sección **Releases** de GitHub contiene `its_4_s3cr3_t-windows-x64.exe` y su
archivo SHA-256. El ejecutable no requiere instalar Python. Comprueba siempre su
huella antes de abrirlo.

## Instalación desde el código

Requiere Python 3.10 o superior.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python run.py
```

En Linux o macOS, activa el entorno con `source .venv/bin/activate`.

## Automatización avanzada (opcional)

No necesitas estos comandos para usar la aplicación: todas las opciones están en
`python run.py`. Se conservan para scripts y automatizaciones:

```text
python run.py encrypt
python run.py decrypt
python run.py generate-password --length 32
python run.py password-strength
python run.py hash-file --file archivo.zip --algorithm sha256
python run.py verify-hash --file archivo.zip --expected HUELLA
python run.py totp
python run.py scan-secrets --path ./mi-proyecto
python run.py inspect-url --url https://ejemplo.com
python run.py compact
python run.py expand
python run.py list
```

Las contraseñas y semillas TOTP no se aceptan como argumentos para evitar que
queden en el historial o en la lista de procesos. `scan-secrets` devuelve código
de salida `1` si encuentra posibles credenciales, por lo que también puede usarse
en automatizaciones defensivas.

## Compresión y longitud

`compact` comprime el texto con DEFLATE y codifica el resultado en Base85. La
salida comienza con `CZ1.` y puede copiarse como una sola línea. La aplicación
muestra la longitud inicial, final y el porcentaje ahorrado.

Base85 puede incluir símbolos especiales de terminal. Para restaurar o descifrar,
abre `python run.py`, selecciona **Recuperar texto** y pega cualquier token
`S4S1`, `S4S2` o `CZ1`; el formato se detecta automáticamente.

La reducción depende del contenido: 230 caracteres repetitivos pueden quedar en
menos de 50, mientras que datos aleatorios o ya comprimidos pueden crecer. No
existe una forma sin pérdida de garantizar que todo texto de 201 caracteres se
reduzca a 50 o 150. `CZ1` **no cifra**; cualquiera puede restaurar su contenido.

## Diseño de seguridad del cifrado

El contenedor actual `S4S2` es propio del proyecto y puede abrir tokens `S4S1`
anteriores, pero la criptografía no se reinventa:

- `scrypt` deriva una clave desde tu contraseña usando una sal aleatoria.
- `AES-256-GCM` cifra y autentica el contenido.
- DEFLATE comprime antes de cifrar solo cuando realmente reduce el tamaño; no
  debes ejecutar `compact` antes de proteger un texto.
- Base85 representa el paquete con menos caracteres que Base64.
- Cada operación usa sal y nonce nuevos, así que la misma frase produce
  resultados diferentes.
- La contraseña nunca se guarda en el resultado ni en el repositorio.

No existe recuperación de contraseña. Conserva el resultado y la contraseña por
separado. Para información crítica o compartida, usa un gestor de contraseñas
auditado.

## Desarrollo y pruebas

```powershell
python -m pip install -e ".[build]"
python -m unittest discover -s tests -v
python -m PyInstaller --onefile --console --clean --name its_4_s3cr3_t run.py
```

GitHub Actions ejecuta las pruebas en Windows y Linux. Cada etiqueta `v*` genera
y publica automáticamente el ejecutable de Windows junto con su SHA-256.

Consulta [SECURITY.md](SECURITY.md) antes de añadir funciones nuevas.
