# Tarea 3 de Redes

Esta tarea fue hecha en python utilizando modulos de la librería estandar,
por lo que no es necesario instalar dependencias adicionales, recomiendo usar 
alguna distribución de linux para ejecutarla ya que solo la he probado en Debian,
la versión de python que utilicé para probar la tarea es la 3.11.2.


## Como ejecutar 

Como se especifica en el enunciado, la tarea se debe ejecutar en varias terminales
de manera simultanea para crear una red:

```bash
python3 fragmentizador.py 127.0.0.1:55551 127.0.0.1:55552:2000 127.0.0.1:55553:3000
python3 fragmentizador.py 127.0.0.1:55552 127.0.0.1:55553:3000 127.0.0.1:55554:4000
python3 fragmentizador.py 127.0.0.1:55553 127.0.0.1:55554:4000
python3 fragmentizador.py 127.0.0.1:55554 127.0.0.1:55555:5000
python3 fragmentizador.py 127.0.0.1:55555 127.0.0.1:55551:1000
```

Los datagramas que pasan por la red necesitan que cada segmento tenga un header
especifico, por lo que no es posible comunicarse con la red utilizando herramientas 
externas como `netcat`, para enviar un datagrama por la red existe la flag `--enviar`
del fragmentizador, la cual se utiliza de la siguiente manera:

```bash
python3 fragmentizador.py --enviar archivo ip_partida:puerto_partida ip_destino:puerto_destino ttl
```

En este comando, `archivo` representa un archivo con los datos que se quieren enviar,
`ip_partida` y `puerto_partida` representan la dirección en la que el datagrama va a partir,
mientras que `ip_destino` y `puerto_destino` representan la dirección a la que el datagrama
debe ser ruteado, finalmente, `ttl` es el tiempo de vida que se le desea dar al datagrama.

No hay restricción con respecto al tamaño del archivo que se envie, pero si este demasiado grande 
en comparación a los MTUs elegidos, la cantidad de datagramas que se creen al fragmentarlo va a
desbordar la cola del sistema operativo, causando que se pierdan datagramas incluso en localhost,
esto me pasó durante el testing y se puede confirmar con el comando:

```bash|
echo start | sudo dropwatch -l kas
```


