# trazas

**Logs de ataque realistas y etiquetados para probar reglas de detección, sin necesidad de un laboratorio.**

🇬🇧 [Read in English](README.md)

Escribir una detección es fácil; demostrar que funciona es lo difícil. La mayoría no
tiene un laboratorio con controladores de dominio, atacantes y meses de tráfico normal.
`trazas` genera esos datos por vos: cadenas de ataque mapeadas a MITRE ATT&CK, mezcladas
con ruido benigno (incluidos eventos parecidos que **no** deberían disparar tu regla) y
con etiquetas opcionales de verdad base para medir verdaderos y falsos positivos.

```console
$ pip install trazas
$ trazas generate windows-bruteforce psexec-lateral --seed 42 --labels -o dataset.jsonl
```

## Por qué importan los eventos parecidos

Una primera regla típica para volcado de credenciales de LSASS marca las máscaras de
acceso sospechosas:

```kql
SecurityEvent
| where EventID == 10 and TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
```

Corrida sobre `trazas generate lsass-dump --seed 1 --start 2026-01-01T00:00:00Z --noise 2000 --labels`
detecta el ataque, **más 89 falsos positivos**: Defender pide `0x1010` (la misma máscara
que Mimikatz) y el sensor del EDR pide `0x1fffff`. Si en cambio se mira el `CallTrace`:

```kql
SecurityEvent
| where EventID == 10 and TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
// Mirar CÓMO se abrió lsass, no solo la máscara de acceso:
| where CallTrace has_any ("dbgcore.dll", "dbghelp.dll", "comsvcs.dll")  // APIs de minidump
     or CallTrace contains "UNKNOWN("                                     // código ejecutándose desde memoria
```

→ **1 verdadero positivo, 0 falsos positivos**, con las tres variantes de volcado (las
semillas 1, 5 y 7 dan comsvcs, Mimikatz y procdump). Paso a paso en
[docs/testing-detections.md](docs/testing-detections.md#example-lsass-dumping-and-look-alikes).

## Características

- **Esquemas listos para detección**: los eventos de Windows usan los nombres de columna
  de `SecurityEvent` de Microsoft Sentinel; los de Linux son líneas reales de `auth.log`.
- **Reproducible**: misma `--seed` + `--start` ⇒ salida idéntica byte a byte. Ideal para
  pruebas de regresión de tus reglas en CI.
- **Verdad base**: `--labels` agrega `_trazas.malicious` y `_trazas.technique` a cada registro,
  o `--labels-file` la guarda en un archivo aparte para probar reglas a ciegas.
- **Ruido realista**: inicios de sesión normales, uso de recursos compartidos, errores de
  contraseña honestos y software de seguridad accediendo a `lsass.exe`.
- **Huecos de telemetría**: `--drop-field` / `--truncate-field` quitan o recortan campos en una
  parte de los eventos, para ver qué hace tu regla cuando los datos llegan incompletos.
- **Seguro por diseño**: las IP externas salen solo de rangos de documentación (RFC 5737),
  las internas de RFC 1918 y los dominios de `example.com`. Cero dependencias en tiempo de
  ejecución.

## Escenarios

| ID | Plataforma | ATT&CK | Qué pasa |
|---|---|---|---|
| `windows-bruteforce` | Windows | T1110.001 | Ráfaga de 4625 contra una cuenta desde una IP externa, luego 4624 |
| `windows-spray` | Windows | T1110.003 | Una contraseña contra muchas cuentas, lento, con un acierto |
| `psexec-lateral` | Windows | T1021.002, T1569.002 | 4624 tipo 3 → 5140 `ADMIN$` → 7045 `PSEXESVC` → Sysmon 1 como SYSTEM |
| `lsass-dump` | Windows | T1003.001 | Sysmon 1 del volcador (comsvcs `MiniDump`, `procdump -ma` o Mimikatz renombrado) → Sysmon 10 sobre `lsass.exe` → Sysmon 11 `.dmp`; el ruido añade accesos benignos de Defender/EDR a lsass |
| `ssh-bruteforce` | Linux | T1110.001 | Fallos de sshd con usuarios comunes y luego `Accepted password` |

## Probar una regla KQL sin Sentinel

1. Creá un [clúster gratuito de Azure Data Explorer](https://dataexplorer.azure.com/freecluster).
2. Corré `trazas schema` y ejecutá en el editor de consultas de ADX los comandos que imprime,
   **antes de la primera carga**. Así se crean las tablas con todas las columnas y los tipos
   correctos desde el principio. Si no, ADX deduce las
   columnas de las primeras filas y puede dejar fuera algunas menos frecuentes, como `CallTrace`
   de Sysmon.
3. Generá datos: `trazas generate windows-bruteforce windows-spray -s 1 --labels -o events.jsonl`
4. Ingerí `events.jsonl` en la tabla existente `SecurityEvent` (formato JSON).
5. Corré tu regla y compará con `_trazas.malicious`. Para probar a ciegas, usá
   `--labels-file etiquetas.jsonl` en vez de `--labels`: la verdad base queda en otro archivo
   y se cruza por `TrazasEventId`.

Guía completa: [docs/testing-detections.md](docs/testing-detections.md).

## Contribuir

¡Los escenarios nuevos son bienvenidos! Mirá [CONTRIBUTING.md](CONTRIBUTING.md). Los
problemas de seguridad se reportan en privado según [SECURITY.md](SECURITY.md).
