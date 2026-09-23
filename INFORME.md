# Informe — Parte 1 (Entrega 1): arquitectura inicial

Laboratorio FDSI: "Aplicación web pública por HTTP: construir, atacar, detectar,
corregir y verificar"

> Este informe documenta la **versión inicial, deliberadamente insegura** del sistema
> (HTTP en claro, sin autenticación ni hardening). La versión fortalecida está en
> [`INFORME_PARTE2.md`](INFORME_PARTE2.md), y la comparación entre ambas, en el
> [`README.md`](README.md#parte-1-vs-parte-2--qué-cambió-y-qué-descubrimos).

**Diagramas de la Parte 1:**

| Diagrama | Archivo |
|---|---|
| DFD del prototipo (Fase B) | [`diagrams/dfd-lab3.png`](diagrams/dfd-lab3.png) |
| Arquitectura inicial: protocolo, puertos y punto de logs | [`diagrams/arquitectura-inicial.jpeg`](diagrams/arquitectura-inicial.jpeg) |

---

## 1. Portada y datos del equipo

- **Proyecto:** MuvAutomation — Automatización de incidentes de CrowdStrike Falcon (prototipo de laboratorio, datos ficticios)
- **Laboratorio:** Lab 3 — Aplicación web pública por HTTP
- **Entrega:** 1 (Fase A — Construir y publicar / Fase B — Modelar antes de atacar)
- **Integrantes:**
  - Ana Gabriela Fiquitiva Poveda
  - Juan David Valero Abril
- **Repositorio:** `FDSI_LAB3_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar`
- **Commit evaluado:** `a3d4681` ("lab3: fase A (API FastAPI + nginx) y fase B (DFD + STRIDE)")
- **Fecha del informe:** 2026-09-12

---

## 2. Descripción del proyecto

**Problema seleccionado:** la recepción, clasificación y escalamiento de alertas de
seguridad (por ejemplo, de CrowdStrike Falcon) hoy depende de actividades manuales, lo
que aumenta el tiempo de respuesta y produce criterios inconsistentes al priorizar
incidentes.

**Objetivo de la primera versión:** construir y publicar una API HTTP mínima que reciba
alertas ficticias, las almacene y permita consultarlas, dejando registro de cada acción
— sin resolver todavía autenticación, cifrado ni los motores de clasificación/escalamiento
(eso es diseño objetivo para fases posteriores).

**Usuarios previstos:** un actor externo simulado (**CrowdStrike Falcon**, generador de
alertas) que envía alertas por `POST /alerts`, y un **Analista SOC** que consulta el
estado de las alertas por `GET /alerts` / `GET /alerts/{id}` y registra las acciones que
toma.

**Datos ficticios que utilizará:** alertas sintéticas con severidad, táctica/técnica
MITRE ATT&CK y hostname de laboratorio (p. ej. `WEB-LAB-01`, severidad `high`, técnica
`T1078 - Valid Accounts`). No se usa información real ni integración real con
CrowdStrike Falcon.

**Alcance y exclusiones:** incluye la API de ingesta y consulta de alertas (FastAPI),
persistencia en SQLite, Nginx como reverse proxy en el puerto 80 y registro de acciones
en archivo. Excluye explícitamente: autenticación/autorización, HTTPS, el Motor de
Clasificación y Enriquecimiento, el Motor de Escalamiento y las notificaciones al
analista (diseñados en el DFD pero no implementados); todo esto queda fuera de esta
entrega a propósito, según el alcance mínimo e inseguro que exige el Lab 3.

**Resultado esperado del despliegue:** la API debe quedar accesible por HTTP a través de
Nginx en el puerto 80 de un servidor Ubuntu del laboratorio, respondiendo con datos
ficticios y dejando evidencia verificable (logs y capturas) de que el servicio está
activo, previo a las fases de ataque (Red Team) y detección (Blue Team).

---

## 3. Arquitectura implementada

![DFD - Automatización de incidentes CrowdStrike Falcon](diagrams/dfd-lab3.png)

El DFD representa el diseño objetivo del prototipo de automatización de incidentes:

- **CrowdStrike Falcon (simulado)** — generador externo de alertas ficticias. Envía una
  alerta en JSON hacia la API mediante `POST /alerts`.
- **API Receptor de Alertas (`POST /alerts`)** — recibe la alerta y la inserta cruda en
  la base de datos.
- **Alerts DB (alertas + estado)** — almacenamiento central; guarda cada alerta y su
  estado (nueva, clasificada, escalada, etc.).
- **Motor de Clasificación y Enriquecimiento** — toma las alertas de la base de datos,
  las enriquece y actualiza su clasificación/score.
- **Motor de Escalamiento** — prioriza las alertas ya clasificadas y, cuando corresponde
  (severidad alta/crítica), genera una notificación de escalamiento hacia el analista.
- **API de Consulta (`GET /alerts?filtros`)** — permite al Analista SOC consultar el
  estado de las alertas con filtros y recibe la respuesta en JSON.
- **Analista SOC** — actor externo que recibe notificaciones de escalamiento, consulta
  alertas y registra las acciones que toma.
- **Registro de Acciones (audit log)** — almacena cada acción tomada por el analista,
  para trazabilidad (mitiga Repudiation).

El diagrama marca un único **límite de confianza** ("Backend del prototipo") que engloba
los componentes de procesamiento; los actores externos quedan fuera. De lo anterior, en
la Parte 1 están construidos la API Receptor, la API de Consulta, la Alerts DB (SQLite) y
una versión inicial del Registro de Acciones (`logs/actions.log`); los motores de
clasificación y escalamiento son diseño objetivo, todavía no implementado.

Como ese DFD se centra en el flujo de datos del negocio (alertas) y no rotula protocolo ni
puertos, se complementa con el siguiente diagrama de arquitectura, que sí identifica
explícitamente protocolo, puertos y el punto de generación de logs:

![Arquitectura implementada - protocolo, puertos y punto de logs](diagrams/arquitectura-inicial.jpeg)

La tabla siguiente resume ambos diagramas en un solo lugar:

| Elemento | Detalle |
|---|---|
| **Actores** | `CrowdStrike Falcon (simulado)` (genera alertas), `Analista SOC` (consulta y registra acciones), `Usuario anónimo` (cualquier cliente HTTP que llega por Nginx) |
| **Componentes** | Nginx (reverse proxy), FastAPI/uvicorn (API Receptor + API de Consulta, un solo proceso hoy), SQLite (`app/alerts.db`). *Diseño objetivo aún no construido:* Motor de Clasificación y Enriquecimiento, Motor de Escalamiento |
| **Flujos de datos** | Alerta ficticia JSON (Falcon → API, `POST /alerts`) · inserción cruda en la DB · consulta de estado (Analista SOC ↔ API, `GET /alerts`, `GET /alerts/{id}`) · registro de acción tomada (→ audit log) |
| **Protocolo** | HTTP/1.1 en claro, sin TLS |
| **Puertos** | `80/tcp` público (Nginx) → `127.0.0.1:8000` interno/loopback (uvicorn, no expuesto directamente a la red) |
| **Almacenes de datos** | `app/alerts.db` (SQLite, tabla `alerts`) · `logs/actions.log` (audit log de acciones, JSON por línea) |
| **Límites de confianza** | Uno solo, rotulado "Backend del prototipo" en el DFD: engloba Nginx, FastAPI y SQLite; los actores externos (Falcon simulado, Analista SOC) quedan fuera |
| **Punto de generación de logs** | Función `log_action()` en `app/main.py` (línea 130 en el commit `a3d4681`), invocada en cada endpoint; escribe a `logs/actions.log`. Nginx genera además su propio `access.log`/`error.log` por defecto (extractos capturados en la sección 6) |

---

## 4. Estructura del repositorio

Árbol de archivos versionados en la Parte 1 (commit `a3d4681`; la estructura actual,
con los archivos de la Parte 2, está en el [`README.md`](README.md)):

```
app/
├── main.py                    # API FastAPI: alertas + registro de acciones
└── requirements.txt
nginx/
└── muvautomation.conf         # virtual host: reverse proxy :80 -> 127.0.0.1:8000
deploy/
└── muvautomation-api.service  # unidad systemd para el Ubuntu Server del laboratorio
diagrams/
├── dfd-lab3.png                # DFD del prototipo (Fase B)
└── arquitectura-inicial.jpeg   # diagrama de protocolo/puertos/log (complementa el DFD)
evidencias/
├── Capturas_FDSI_LAB3.pdf       # capturas reales del despliegue en Ubuntu (sección 6)
└── local-http-server/
    └── index.html               # evidencia del comando python3 -m http.server (sección 5)
README.md
INFORME.md                      # este informe
```

`app/alerts.db` y `logs/actions.log` se generan en tiempo de ejecución y están
excluidos de git vía `.gitignore` (no se versiona estado ni datos generados).

---

## 5. Evidencias de ejecución local

**Nota sobre los comandos:** el enunciado sugiere `python3 -m http.server 8080` sirviendo
un `index.html`. Este proyecto no tiene frontend estático — el "índice" lo genera
FastAPI en memoria — así que la evidencia principal usa el stack real (`uvicorn`
sirviendo en `127.0.0.1:8000`). Para cumplir también con el comando literal del
enunciado, se agregó un `index.html` mínimo de evidencia en
`evidencias/local-http-server/index.html` (aclarado en el propio archivo como
complementario, no parte de la app en producción) y se ejecutó `http.server` sobre él:

Los comandos de `git`/`find` se ejecutaron el **2026-09-12** sobre el working tree
local (rama `main`, working tree limpio, sincronizado con `origin/main`); las pruebas de
`http.server` y `uvicorn` llevan su propia fecha/hora exacta junto a cada bloque.

**`git status`**
```
On branch main
Your branch is up to date with 'origin/main'.

nothing to commit, working tree clean
```

**`git log --oneline -5`**
```
a3d4681 lab3: fase A (API FastAPI + nginx) y fase B (DFD + STRIDE)
2a227b1 Initial commit
```

**`find . -maxdepth 3 -type f`** (excluyendo `.git/` y el entorno virtual)
```
./.gitignore
./app/alerts.db
./app/main.py
./app/requirements.txt
./app/__pycache__/main.cpython-311.pyc
./deploy/muvautomation-api.service
./diagrams/dfd-lab3.png
./logs/actions.log
./nginx/muvautomation.conf
./README.md
```

**Comando literal del enunciado** (`python3 -m http.server 8080` sobre el `index.html`
de evidencia):
```
$ cd evidencias/local-http-server
$ python -m http.server 8080
```

**Fecha/hora de la prueba (UTC):** `2026-09-13T02:41:44Z`

```
$ curl -sS -I http://localhost:8080
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.9
Date: Sun, 13 Sep 2026 02:41:45 GMT
Content-type: text/html
Content-Length: 647
Last-Modified: Sun, 13 Sep 2026 02:41:18 GMT
```
→ **Código HTTP obtenido: 200 OK.**

```
$ curl -sS http://localhost:8080
<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>MuvAutomation - Evidencia http.server (Lab 3)</title></head>
<body>
  <h1>MuvAutomation - Falcon Incident Automation (LAB)</h1>
  <p>Página estática de evidencia para el comando <code>python3 -m http.server 8080</code>
     exigido por el enunciado de la Entrega 1.</p>
  ...
</body>
</html>
```

**Levantar la aplicación real del laboratorio** (FastAPI/uvicorn, stack efectivamente
usado en producción):
```
cd app
.venv/Scripts/uvicorn main:app --host 127.0.0.1 --port 8000
```

**Fecha/hora de la prueba (UTC):** `2026-09-12T16:03:13Z`

**`curl -I` equivalente** (GET solo cabeceras — la ruta `/` no admite `HEAD`, por eso se
usó `curl -D - -o /dev/null` en vez de `-I` literal):
```
$ curl -sS -D - -o /dev/null http://127.0.0.1:8000/
HTTP/1.1 200 OK
date: Sat, 12 Sep 2026 16:03:12 GMT
server: uvicorn
content-length: 367
content-type: text/html; charset=utf-8
```
→ **Código HTTP obtenido: 200 OK.**

**`curl http://localhost:8000/`** (cuerpo de la respuesta)
```html
<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>MuvAutomation Falcon Lab</title></head>
<body>
  <h1>MuvAutomation - Falcon Incident Automation (LAB)</h1>
  <p>Environment: LAB</p>
  <p>Owner: Blue Team</p>
  <p>Datos ficticios. Endpoints: <code>POST /alerts</code>, <code>GET /alerts</code>,
     <code>GET /alerts/{id}</code></p>
</body>
</html>
```

**Prueba funcional adicional** (`POST /alerts` con dato ficticio → `GET /alerts` →
`GET /alerts/no-existe`), confirma que la API persiste y expone datos, y que responde
404 ante un recurso inexistente:
```
$ curl -sS -i -X POST http://127.0.0.1:8000/alerts -H "Content-Type: application/json" \
  -d '{"severity":"high","tactic":"Initial Access","technique":"T1078 - Valid Accounts","hostname":"WEB-LAB-01","description":"Prueba de evidencia local Entrega 1 (dato ficticio)"}'
HTTP/1.1 201 Created
...
{"severity":"high", ... ,"id":"79177e32-0357-410f-942c-34780cbf031e","created_at":"2026-09-12T16:03:13.526567+00:00","status":"new"}

$ curl -sS -i http://127.0.0.1:8000/alerts
HTTP/1.1 200 OK
...

$ curl -sS -i http://127.0.0.1:8000/alerts/no-existe
HTTP/1.1 404 Not Found
...
{"detail":"Alert not found"}
```

**Extracto de `logs/actions.log`** generado durante estas pruebas (confirma el punto de
generación de logs descrito en la sección 3):
```
{"timestamp": "2026-09-12T16:03:13.324790+00:00", "action": "view_root", "method": "GET", "path": "/", "client_ip": "127.0.0.1", "alert_id": null}
{"timestamp": "2026-09-12T16:03:13.543129+00:00", "action": "create_alert", "method": "POST", "path": "/alerts", "client_ip": "127.0.0.1", "alert_id": "79177e32-0357-410f-942c-34780cbf031e"}
{"timestamp": "2026-09-12T16:03:13.631756+00:00", "action": "list_alerts", "method": "GET", "path": "/alerts", "client_ip": "127.0.0.1", "alert_id": null}
{"timestamp": "2026-09-12T16:03:13.734951+00:00", "action": "get_alert_not_found", "method": "GET", "path": "/alerts/no-existe", "client_ip": "127.0.0.1", "alert_id": "no-existe"}
```

**Esto demuestra:** el repositorio está clonado y actualizado (`git status`/`git log`),
el `index.html` de evidencia existe y `http.server` lo sirve con HTTP 200
(`evidencias/local-http-server/index.html`), la aplicación real (`app/main.py`, sin
frontend estático) funciona localmente (HTTP 200 en `/`, 201 en creación, 404 en recurso
inexistente), el commit evaluado es `a3d4681`, y las fechas/horas exactas de las pruebas
son `2026-09-13T02:41:44Z` (http.server) y `2026-09-12T16:03:13Z` (uvicorn/API real).

---

## 6. Evidencias del servidor y Nginx

**Estado: completado.** El prototipo fue desplegado en un servidor Ubuntu real
(`lab3-server`, VM VMware, red NAT local) el **2026-09-13**. A continuación la evidencia
recolectada durante el despliegue, respaldada por las capturas de pantalla reales en
[`evidencias/Capturas_FDSI_LAB3.pdf`](evidencias/Capturas_FDSI_LAB3.pdf):

- **Página 1:** `hostnamectl`, `ip -br address`, `uname -a`, `date -u`, `whoami`, `pwd`,
  `nginx -v` y `sudo nginx -t` — todos ejecutados directamente en la terminal SSH del
  servidor `lab3-server`.
- **Página 2:** `systemctl status nginx --no-pager` y
  `systemctl status muvautomation-api --no-pager` (ambos servicios `active (running)`),
  más el log en vivo de `uvicorn` mostrando peticiones reales entrantes (incluida una
  desde `192.168.61.1`, el host Windows), y `curl -I`/`curl -i` contra `localhost`
  mostrando `405`/`200 OK` con cabeceras de `nginx/1.28.3`.
- **Página 3: captura real del navegador** cargando `http://192.168.61.129` y mostrando
  la página "MuvAutomation - Falcon Incident Automation (LAB)" — evidencia visual
  exigida por el enunciado — junto con `cat nginx/*.conf` confirmando la configuración
  desplegada.
- **Página 4:** `ls -la /opt/fdsi-lab3` (permisos del directorio publicado),
  `tail -n 20` de `access.log` y `error.log`, y `sudo ufw status numbered` con las
  reglas finales del firewall.

**Host y usuario:**
```
$ hostname          → lab3-server
$ whoami            → ubuntu
$ pwd               → /opt/fdsi-lab3
```

**Línea base del host** (`hostnamectl`, `2026-09-13T01:43:28Z`):
```
Static hostname: lab3-server
Operating System: Ubuntu 26.04.1 LTS
Kernel: Linux 7.0.0-31-generic
Architecture: x86-64
Virtualization: vmware
```
`ip -br address` → `ens33 UP 192.168.61.129/24`. `uname -a` →
`Linux lab3-server 7.0.0-31-generic ... x86_64 GNU/Linux`.

**Versión e instalación de Nginx:**
```
$ sudo apt install -y nginx python3-venv
Configurando nginx (1.28.3-2ubuntu1.10) ...
$ nginx -v
nginx version: nginx/1.28.3 (Ubuntu)
```

**Prueba de sintaxis y estado del servicio:**
```
$ sudo nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful

$ sudo systemctl status nginx --no-pager
● nginx.service - A high performance web server and a reverse proxy server
     Active: active (running) since Sun 2026-09-13 01:44:34 UTC
   Main PID: 2292 (nginx)

$ sudo systemctl status muvautomation-api --no-pager
● muvautomation-api.service - MuvAutomation Falcon Incident Lab API (Lab 3 - HTTP sin autenticacion)
     Active: active (running) since Sun 2026-09-13 01:57:20 UTC; 6s ago
   Main PID: 2816 (uvicorn)
```

**Acceso HTTP verificado (por Nginx, puerto 80):**
```
$ curl -i http://localhost
HTTP/1.1 200 OK
Server: nginx/1.28.3 (Ubuntu)
Content-Type: text/html; charset=utf-8
Content-Length: 367
```
→ **Código HTTP obtenido: 200 OK.** (`curl -I` da 405 porque envía `HEAD` y la ruta `/`
solo implementa `GET`, igual que en la evidencia local de la sección 5 — comportamiento
consistente entre entorno local y servidor.)

**Captura del navegador / URL utilizada:** desde el host Windows, `http://192.168.61.129`
cargó correctamente la misma página que devuelve el `curl`. *(Red NAT local de VMware —
no hay IP pública real de laboratorio asignada; se usó este segmento como adaptación
equivalente, ver nota de firewall más abajo).*

**Archivo de configuración de Nginx desplegado** (`/etc/nginx/sites-available/fdsi-lab3`,
copiado sin cambios desde `nginx/muvautomation.conf`):
```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Permisos del directorio publicado** (`ls -la /opt/fdsi-lab3`):
```
drwxr-xr-x 9 ubuntu www-data 4096 Sep 13 01:56 .
drwxrwxr-x 7 ubuntu www-data 4096 Sep 13 01:51 .git
drwxrwxr-x 5 ubuntu www-data 4096 Sep 13 01:52 .venv
drwxrwxr-x 3 ubuntu www-data 4096 Sep 13 01:57 app
drwxrwxr-x 2 ubuntu www-data 4096 Sep 13 01:57 logs
```
Propietario `ubuntu`, grupo `www-data` (el usuario bajo el que corre el servicio
systemd), con permisos de grupo de lectura/ejecución (`chmod g+rX`) — el servicio puede
leer el código sin correr como root ni como el usuario interactivo.

**Extracto de `access.log`** (sin datos sensibles):
```
::1 - - [13/Sep/2026:01:59:51 +0000] "HEAD / HTTP/1.1" 405 0 "-" "curl/8.18.0"
::1 - - [13/Sep/2026:02:00:07 +0000] "GET / HTTP/1.1" 200 367 "-" "curl/8.18.0"
192.168.61.1 - - [13/Sep/2026:02:00:37 +0000] "GET / HTTP/1.1" 200 260 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
192.168.61.1 - - [13/Sep/2026:02:00:37 +0000] "GET /favicon.ico HTTP/1.1" 404 22 "http://192.168.61.129/" "Mozilla/5.0 ..."
```

**Extracto de `error.log`:**
```
2026/09/13 01:44:35 [notice] 2292#2292: using inherited sockets from "5;6;"
```
Sin errores reales registrados: el despliegue no presentó incidentes de configuración
en Nginx.

**Firewall (ufw):** limitado al segmento `192.168.61.0/24` (red NAT local de VMware,
usada como adaptación al no tener asignado un CIDR oficial de laboratorio) más
`OpenSSH` para administración:
```
Status: active
[1] OpenSSH        ALLOW IN   Anywhere
[2] 80/tcp         ALLOW IN   192.168.61.0/24
[3] OpenSSH (v6)   ALLOW IN   Anywhere (v6)
```

**Observación de higiene del repositorio:** para poder ejecutar `git clone` por HTTPS
sin configurar un token, el repositorio se puso **temporalmente en público** durante el
despliegue. Esto no es una vulnerabilidad de la aplicación, pero es una decisión de
manejo de acceso que debe revertirse (o reemplazarse por un despliegue con token/deploy
key) antes de considerar el repositorio "cerrado" para el resto del curso.

**Esto demuestra:** el servidor Ubuntu (`lab3-server`, Ubuntu 26.04.1 LTS) tiene Nginx
1.28.3 activo y con sintaxis válida, el servicio `muvautomation-api` corre bajo systemd,
la API responde HTTP 200 tanto directo (`127.0.0.1:8000`) como a través de Nginx
(puerto 80), el acceso está limitado por `ufw` al segmento de laboratorio, y los
permisos del directorio publicado siguen el principio de mínimo privilegio para el
usuario de servicio.

---

## 7. Diagnóstico del fallo

El despliegue de la aplicación y de Nginx en sí no presentó fallos (sección 6: `nginx -t`
con sintaxis correcta, servicio activo, HTTP 200 en local y a través de Nginx). Sí ocurrió
un **incidente real durante el endurecimiento del firewall (`ufw`)**, que se documenta
aquí siguiendo el mismo formato de diagnóstico:

| Prueba | Esperado | Obtenido | Evidencia | Causa |
|---|---|---|---|---|
| `curl localhost` (Nginx) | HTTP 200 | HTTP 200 | Sección 6, punto "Acceso HTTP verificado" | N/A — sin fallo |
| `nginx -t` | Syntax OK | Syntax OK | Sección 6, punto "Prueba de sintaxis" | N/A — sin fallo |
| Nueva conexión SSH tras `sudo ufw enable` | Conexión SSH exitosa | `ssh: connect to host 192.168.61.129 port 22: Connection timed out` | Salida de `ufw status numbered` sin reglas `allow` visibles justo después de habilitar `ufw` | Se ejecutó `ufw default deny incoming` + `ufw enable` **antes** de crear la regla `allow OpenSSH`; el firewall quedó denegando SSH para toda conexión nueva |

**Cómo se resolvió:** la sesión SSH original seguía activa (una conexión ya establecida
no se corta al activar `ufw`), lo que permitió, sin perder acceso al servidor, ejecutar:
```bash
sudo ufw allow OpenSSH
sudo ufw allow from 192.168.61.0/24 to any port 80 proto tcp
```
Una conexión SSH nueva desde otra terminal confirmó que quedó resuelto. **Lección para
futuros despliegues:** siempre crear las reglas `allow` (en particular `OpenSSH`) *antes*
de `ufw enable`, o abrir una segunda sesión de respaldo antes de tocar el firewall.

---

## 8. Modelo de amenazas inicial

**DFD:**

![DFD - Automatización de incidentes CrowdStrike Falcon](diagrams/dfd-lab3.png)

**Activos:**
- `app/alerts.db` (alertas: severidad, táctica/técnica, hostname, estado)
- `logs/actions.log` (registro/auditoría de acciones)
- Disponibilidad del servicio (API Receptor y API de Consulta)
- Integridad de la clasificación/estado de cada alerta

**Actores:**
- `CrowdStrike Falcon (simulado)` — externo, genera alertas
- `Analista SOC` — externo, consulta y actúa sobre alertas
- `Usuario anónimo` — cualquier cliente HTTP no diferenciado (no hay autenticación)

**Límites de confianza:** uno solo, "Backend del prototipo" (Nginx + FastAPI + SQLite);
todo actor externo es no confiable por defecto porque no hay autenticación.

**Superficie de ataque:** `POST /alerts` (sin validación de origen ni de tasa),
`GET /alerts` y `GET /alerts/{id}` (sin autenticación ni control de campos expuestos),
el archivo `alerts.db` en disco (sin cifrado ni control de integridad), y el propio
Nginx (sin `server_tokens off` ni cabeceras de seguridad).

**Riesgos STRIDE (uno por categoría), evidencia asociada y mitigación propuesta:**

| ID | STRIDE | Elemento afectado | Hipótesis de amenaza | Evidencia / prueba asociada | Mitigación propuesta |
|----|--------|--------------------|------------------------|-------------------------------|------------------------|
| H1 | Spoofing | `POST /alerts` | Un origen no autorizado puede enviar alertas haciéndose pasar por CrowdStrike Falcon; el endpoint no valida origen ni credenciales. | **Verificable hoy**: el `POST /alerts` ejecutado en la sección 5 fue aceptado (HTTP 201) sin ninguna credencial. | Exigir un token/API-key compartido o mTLS entre el generador de alertas y la API. |
| H2 | Tampering | `app/alerts.db` | Una alerta almacenada puede modificarse (severidad, estado) directamente en el archivo SQLite, sin dejar rastro de quién lo hizo. | Pendiente de prueba (requiere acceso al archivo en el servidor desplegado). | Mover a un motor con control de integridad/transacciones auditadas, o firmar/hashear cada registro. |
| H3 | Repudiation | `logs/actions.log` (audit log) | El log asocia IP y acción, pero no un analista autenticado; alguien podría negar haber tomado una acción. | **Verificable hoy**: el extracto de la sección 5 muestra `client_ip` pero ningún identificador de usuario. | Autenticar al Analista SOC y registrar su identidad en cada entrada del log. |
| H4 | Information Disclosure | `GET /alerts` | La API expone todos los campos de todas las alertas a cualquiera que la consulte, sin filtros por rol. | **Verificable hoy**: `GET /alerts` en la sección 5 devolvió las 4 alertas completas sin autenticación. | Requerir autenticación y aplicar control de acceso por rol/campo antes de responder. |
| H5 | Denial of Service | API Receptor (`POST /alerts`) / proceso `uvicorn` | Un volumen alto de alertas ficticias enviadas rápidamente podría agotar el proceso único de `uvicorn` y retrasar alertas legítimas. | Pendiente de prueba de carga (no ejecutada en esta entrega). | Añadir `limit_req` en Nginx y límites de tamaño/tasa en la API. |
| H6 | Elevation of Privilege | Motor de Escalamiento (diseño objetivo, no construido) | Cuando exista, un analista de bajo privilegio podría forzar un escalamiento sin el rol adecuado. | No aplica todavía (componente no implementado). | Diseñar el control de autorización por rol desde el inicio del motor, antes de construirlo. |

**Nota:** las hipótesis se validan solo con datos ficticios de laboratorio, sin exponer
información real de CrowdStrike Falcon.

---

## 9. Conclusión

La Fase A (construir y publicar una API HTTP mínima) y la Fase B (modelar amenazas antes
de atacar) están completas, tanto a nivel de código/diseño como de despliegue real: existe
una API FastAPI funcional con persistencia SQLite, Nginx activo como reverse proxy en un
servidor Ubuntu real (`lab3-server`, `192.168.61.129`), un DFD con su límite de confianza
y una tabla STRIDE que cubre las 6 categorías con hipótesis, evidencia y mitigación
propuesta cada una. Tanto la evidencia de ejecución local (sección 5) como la de servidor
(sección 6) confirman que el repositorio, el commit y la aplicación funcionan de forma
consistente en ambos entornos (mismo HTTP 200/405 esperado). El único incidente real
detectado — el bloqueo temporal de SSH al activar `ufw` sin reglas previas (sección 7) —
se diagnosticó y corrigió sin pérdida de acceso, y queda documentado como lección
aprendida. Lo pendiente para las siguientes entregas es: revertir la visibilidad pública
temporal del repositorio (o reemplazarla por un método de clonado con credenciales), y
construir/corregir en las Fases C–F los componentes de clasificación/escalamiento y las
limitaciones de seguridad ya documentadas (autenticación, TLS, hardening de Nginx).

---

## Anexo — Procedimiento de despliegue en Ubuntu (paso a paso)

Procedimiento genérico de la Parte 1, documentado antes del despliegue (HTTP :80). La
ejecución real, con las rutas y ajustes específicos del servidor `lab3-server`
(`/opt/fdsi-lab3` en vez de `/opt/muvautomation`, ajuste de `deploy/*.service` con `sed`,
permisos `www-data`, y la corrección del incidente de `ufw`/SSH), queda documentada en
detalle en las secciones 6 y 7 de este informe. El procedimiento de la Parte 2 (HTTPS y
hardening) está en [`INFORME_PARTE2.md`](INFORME_PARTE2.md#8-cambios-implementados).

```bash
# Paso 1 - Verificar host y registrar línea base
hostnamectl
ip -br address
uname -a
date -u +%Y-%m-%dT%H:%M:%SZ

# Paso 2 - Instalar Nginx y Python
sudo apt update
sudo apt install -y nginx python3-venv

# Copiar el repo al servidor, por ejemplo en /opt/muvautomation
sudo mkdir -p /opt/muvautomation
cd /opt/muvautomation
python3 -m venv .venv
.venv/bin/pip install -r app/requirements.txt

# Servicio systemd para la API
sudo cp deploy/muvautomation-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now muvautomation-api
sudo systemctl status muvautomation-api --no-pager

# Virtual host Nginx (reverse proxy)
sudo cp nginx/muvautomation.conf /etc/nginx/sites-available/muvautomation
sudo ln -s /etc/nginx/sites-available/muvautomation /etc/nginx/sites-enabled/muvautomation
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
curl -i http://127.0.0.1/

# Paso 5 - Firewall limitado al segmento del laboratorio
export LAB_CIDR=CIDR_AUTORIZADO
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from "$LAB_CIDR" to any port 80 proto tcp
sudo ufw allow OpenSSH
sudo ufw enable
sudo ufw status numbered
```
