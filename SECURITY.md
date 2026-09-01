# Política de seguridad

Este proyecto reúne utilidades defensivas para proteger información propia y
revisar archivos bajo autorización. No incluye fuerza bruta, explotación,
persistencia, evasión ni escaneo de sistemas remotos.

## Datos sensibles

- El cifrado, TOTP, hashes, contraseñas y análisis de URLs se ejecutan localmente.
- Las contraseñas y secretos TOTP se solicitan con entrada oculta.
- El escáner reporta archivo, línea y tipo, pero nunca imprime la credencial.
- No guardes contraseñas, semillas TOTP o archivos `.secret` en Git.
- `CZ1` solo comprime y codifica: no ofrece confidencialidad. Usa `S4S2` para
  ocultar contenido con contraseña.

El escáner y el analizador de URLs son heurísticos: pueden tener falsos positivos
y no sustituyen una auditoría profesional. Un resultado sin hallazgos no prueba
que un archivo o enlace sea seguro.

## Reportar una vulnerabilidad

No publiques credenciales ni pruebas con datos reales en un issue. Reporta el
problema al propietario del repositorio por un canal privado y proporciona un
caso mínimo que use valores ficticios.
