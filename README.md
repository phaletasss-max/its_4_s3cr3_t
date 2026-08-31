# its_4_s3cr3_t

Caja defensiva y extensible de pequeñas herramientas personales de
ciberseguridad. Todo se ejecuta localmente desde Python y las funciones que
reciben secretos no los envían por internet.

## Herramientas incluidas

1. Cifrado autenticado de palabras o frases en formato propio `S4S1`.
2. Descifrado y detección de contraseñas incorrectas o datos manipulados.
3. Generador criptográfico de contraseñas.
4. Evaluación local de fortaleza mediante `zxcvbn`.
5. Cálculo de hashes SHA-256, SHA-512 y BLAKE2b.
6. Verificación de integridad contra una huella conocida.
7. Creación de secretos y generación de códigos TOTP/2FA con `PyOTP`.
8. Escáner local de credenciales expuestas que nunca imprime el secreto.
9. Análisis estático de URLs sospechosas sin visitar el destino.

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
python run.py list
```

Las contraseñas y semillas TOTP no se aceptan como argumentos para evitar que
queden en el historial o en la lista de procesos. `scan-secrets` devuelve código
de salida `1` si encuentra posibles credenciales, por lo que también puede usarse
en automatizaciones defensivas.

## Diseño de seguridad del cifrado

El contenedor `S4S1` es propio de este proyecto, pero la criptografía no se
reinventa:

- `scrypt` deriva una clave desde tu contraseña usando una sal aleatoria.
- `AES-256-GCM` cifra y autentica el contenido.
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

