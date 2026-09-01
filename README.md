# its_4_s3cr3_t

Caja defensiva y extensible de pequeñas herramientas personales de
ciberseguridad. Todo se ejecuta localmente desde Python y las funciones que
reciben secretos no los envían por internet.

## Herramientas incluidas

1. Cifrado compacto autenticado en formato `S4S2`, compatible con `S4S1`.
2. Descifrado y detección de contraseñas incorrectas o datos manipulados.
3. Generador criptográfico de contraseñas.
4. Evaluación local de fortaleza mediante `zxcvbn`.
5. Cálculo de hashes SHA-256, SHA-512 y BLAKE2b.
6. Verificación de integridad contra una huella conocida.
7. Creación de secretos y generación de códigos TOTP/2FA con `PyOTP`.
8. Escáner local de credenciales expuestas que nunca imprime el secreto.
9. Análisis estático de URLs sospechosas sin visitar el destino.
10. Compresión DEFLATE + codificación Base85 en formato `CZ1`.
11. Restauración exacta de textos compactos `CZ1`.

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

## Comandos directos

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
es más seguro abrir el menú con `python run.py` y pegar allí el token, en lugar
de pasarlo como argumento.

La reducción depende del contenido: 230 caracteres repetitivos pueden quedar en
menos de 50, mientras que datos aleatorios o ya comprimidos pueden crecer. No
existe una forma sin pérdida de garantizar que todo texto de 201 caracteres se
reduzca a 50 o 150. `CZ1` **no cifra**; cualquiera puede restaurar su contenido.

## Diseño de seguridad del cifrado

El contenedor actual `S4S2` es propio del proyecto y puede abrir tokens `S4S1`
anteriores, pero la criptografía no se reinventa:

- `scrypt` deriva una clave desde tu contraseña usando una sal aleatoria.
- `AES-256-GCM` cifra y autentica el contenido.
- DEFLATE comprime antes de cifrar solo cuando realmente reduce el tamaño.
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
