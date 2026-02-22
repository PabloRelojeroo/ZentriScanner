# ZentriScanner (SSTool) v4.0

Una herramienta que desarrollé para prbarme a mi mismo, pero puede llegar a servir en el dia a dia :D

## Características

### Detección de Hack Clients
- Escanea la memoria de procesos java en busca de clientes conocidos
- Base de datos actualizable desde gitHub automáticamente

### MISC Scanner
Analisis completo de caracteristicas que pueden llevar a un bypass attempt.

- **Firewall CPL**: Verifica estado del firewall y reglas
- **Hosts checker**: Detecta modificaciones sospechosas en el archivo hosts
- **DisallowRun**: Verifica políticas de registro que bloquean programas
- **Prefetch Aaalysis**: Analiza programas ejecutados recientemente (en beta)
- **AutoRun**: Detecta programas de inicio automático (inservible)
- **Antivirus detection**: Identifica software de seguridad instalado.
- **BAM**: Analiza BAM.
- **Recent files**: Revisa archivos recent.

### Módulo Doomsday (Mejorado)
Ahora el modulo busca non-jars, aparte de tener una buena taza de deteccion jiji


```

## Uso

Recomendado ejecutar como **administrador** para acceso completo.

### Comandos principales:

```bash
ZentriScanner.exe -v -r # Hace el escaneo con verbose y un reporte TXT al finalizar
```

### Argumentos:

| Argumento | Descripción |
|-----------|-------------|
| `-v`, `--verbose` | Muestra detalles del proceso |
| `-r`, `--report` | Genera un reporte en TXT |
| `--offline` | No intenta descargar clients.json de internet |