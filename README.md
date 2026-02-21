# ZentriScanner (nombre en proceso)

Esta es una herramienta muy simple que busca en el classpaths hacks clients, no es nada sofisticado, solo nos ahorra el trabajo de buscar los strings manualmente

## Como funciona?
Simplemente analiza los procesos de java en busca de clases cargadas coincidentes con hacks clients conocidos, no es nada del otro mundo y es mega bypasseable

Los hacks clients conocidos se leen mediante un archivo json, donde se le indica el nombre de los hack clients + las clases del mismo (para ver sus clases facilmente se puede hacer ```jar -tf archivo.jar```)

Incluí un archivo clients.json como base, pero cualquier pull request que se haga en busca de adiciones la voy a aceptar sin problemas.

## Modulo doomsday completo

Quise experimentar con el journal entonces hice un modulo que busca doomsday, inspirado en el mitico DoomsdayFinder


### ACLARCION
Esta tool es completamente bypasseable, el codigo de la misma por ahora va a ser publico, en dado caso de que tome relevancia lo voy a colutar y obfuscar por obvias razones


# USO
Para usarlo, recomiendo abrir un CMD como admin:

```
ZentriScanner.exe -report -v
```
Esto nos muestra el verbose de lo que está haciendo y lo que hace es dejarnos un reporte de lo encontrado en su carpeta raiz

```
ZentriScanner.exe --doomsday -v
```

Este comando activa el modulo completo de doomsday, usando todos los sistemas de deteccion del mismo que idee.

```
-v # Verbose: detalles del proceso que está haciendo
-report / -r # genera un reporte en TXT de los resultados
--doomsday #  Activa el modulo que intenta buscar doomsday mas a fondo
```