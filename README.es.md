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

## Características

- **Esquemas listos para detección**: los eventos de Windows usan los nombres de columna
  de `SecurityEvent` de Microsoft Sentinel; los de Linux son líneas reales de `auth.log`.
- **Reproducible**: misma `--seed` + `--start` ⇒ salida idéntica byte a byte. Ideal para
  pruebas de regresión de tus reglas en CI.
- **Verdad base**: `--labels` agrega `_trazas.malicious` y `_trazas.technique` a cada registro.
- **Ruido realista**: inicios de sesión normales, uso de recursos compartidos, errores de
  contraseña honestos.
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
2. Generá datos: `trazas generate windows-bruteforce windows-spray -s 1 --labels -o events.jsonl`
3. Ingerí `events.jsonl` en una tabla llamada `SecurityEvent` (formato JSON).
4. Corré tu regla y compará con `_trazas.malicious`.

Guía completa: [docs/testing-detections.md](docs/testing-detections.md).

## Contribuir

¡Los escenarios nuevos son bienvenidos! Mirá [CONTRIBUTING.md](CONTRIBUTING.md). Los
problemas de seguridad se reportan en privado según [SECURITY.md](SECURITY.md).
