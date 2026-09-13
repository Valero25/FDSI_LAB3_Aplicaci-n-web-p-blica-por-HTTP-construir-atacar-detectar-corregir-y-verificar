# Informe — Entrega 1

Laboratorio FDSI: "Aplicación web pública por HTTP: construir, atacar, detectar,
corregir y verificar"

---

## 1. Portada y datos del equipo

- **Proyecto:** MuvAutomation — Automatización de incidentes de CrowdStrike Falcon (prototipo de laboratorio, datos ficticios)
- **Laboratorio:** Lab 3 — Aplicación web pública por HTTP
- **Entrega:** 1 (Fase A — Construir y publicar / Fase B — Modelar antes de atacar)
- **Integrantes:**
  - Juan David Valero Abril
  - Ana Gabriela Fiquitiva Poveda
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

El diagrama completo (actores, procesos, almacenes y límite de confianza) está en
`diagrams/dfd-lab3.png` y descrito en detalle en `README.md` ("Modelo de amenazas —
DFD"). La tabla siguiente complementa el diagrama con los datos que no se rotulan en la
imagen (protocolo, puertos y punto de logs), tal como exige esta entrega:

| Elemento | Detalle |
|---|---|
| **Actores** | `CrowdStrike Falcon (simulado)` (genera alertas), `Analista SOC` (consulta y registra acciones), `Usuario anónimo` (cualquier cliente HTTP que llega por Nginx) |
| **Componentes** | Nginx (reverse proxy), FastAPI/uvicorn (API Receptor + API de Consulta, un solo proceso hoy), SQLite (`app/alerts.db`). *Diseño objetivo aún no construido:* Motor de Clasificación y Enriquecimiento, Motor de Escalamiento |
| **Flujos de datos** | Alerta ficticia JSON (Falcon → API, `POST /alerts`) · inserción cruda en la DB · consulta de estado (Analista SOC ↔ API, `GET /alerts`, `GET /alerts/{id}`) · registro de acción tomada (→ audit log) |
| **Protocolo** | HTTP/1.1 en claro, sin TLS |
| **Puertos** | `80/tcp` público (Nginx) → `127.0.0.1:8000` interno/loopback (uvicorn, no expuesto directamente a la red) |
| **Almacenes de datos** | `app/alerts.db` (SQLite, tabla `alerts`) · `logs/actions.log` (audit log de acciones, JSON por línea) |
| **Límites de confianza** | Uno solo, rotulado "Backend del prototipo" en el DFD: engloba Nginx, FastAPI y SQLite; los actores externos (Falcon simulado, Analista SOC) quedan fuera |
| **Punto de generación de logs** | Función `log_action()` en `app/main.py` (línea 130), invocada en cada endpoint; escribe a `logs/actions.log`. Nginx generará su propio `access.log`/`error.log` por defecto una vez desplegado (pendiente de captura en la sección 6) |

---

## 4. Estructura del repositorio

El detalle completo (propósito, requisitos, ejecución local, procedimiento de
despliegue, URL publicada, integrantes y limitaciones de seguridad conocidas) está en
[`README.md`](README.md). Árbol de archivos versionados:

```
app/
├── main.py                    # API FastAPI: alertas + registro de acciones
└── requirements.txt
nginx/
└── muvautomation.conf         # virtual host: reverse proxy :80 -> 127.0.0.1:8000
deploy/
└── muvautomation-api.service  # unidad systemd para el Ubuntu Server del laboratorio
diagrams/
└── dfd-lab3.png                # DFD del prototipo (Fase B)
README.md
INFORME.md                      # este informe
```

`app/alerts.db` y `logs/actions.log` se generan en tiempo de ejecución y están
excluidos de git vía `.gitignore` (no se versiona estado ni datos generados).

---

## 5. Evidencias de ejecución local

**Nota sobre los comandos:** el enunciado sugiere `python3 -m http.server 8080` sirviendo
un `index.html`. Este proyecto no tiene frontend estático — el "índice" lo genera
FastAPI en memoria — así que los comandos de evidencia se adaptaron al stack real
(`uvicorn` sirviendo en `127.0.0.1:8000`), manteniendo el mismo propósito: repositorio
clonado, aplicación existente y funcionando localmente, commit evaluado y código HTTP
obtenido.

Todos los comandos siguientes se ejecutaron el **2026-09-12** sobre el working tree
local (rama `main`, working tree limpio, sincronizado con `origin/main`).

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

**Levantar la aplicación** (equivalente local a `python3 -m http.server 8080`, adaptado
al stack real):
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
`app/main.py` existe y contiene la aplicación (no hay `index.html` porque no aplica a
este stack), la página/API funciona localmente (HTTP 200 en `/`, 201 en creación, 404 en
recurso inexistente), el commit evaluado es `a3d4681`, y la fecha/hora exacta de las
pruebas es `2026-09-12T16:03:13Z`.

---

## 6. Evidencias del servidor y Nginx

**Estado: pendiente.** A la fecha de este informe, el prototipo **no ha sido desplegado
todavía** en un servidor Ubuntu real del laboratorio — solo se ha verificado en entorno
local (sección 5). Esta sección se completará con evidencia real (capturas, salidas de
comandos, extractos de `access.log`/`error.log`) en cuanto se ejecute el despliegue.

El paso a paso completo para producir esa evidencia está al final de este documento
("Anexo — Procedimiento de despliegue en Ubuntu"), y ya está documentado también en
`README.md` ("Despliegue en el Ubuntu Server del laboratorio"). Checklist de lo que debe
capturarse una vez desplegado (sin incluir contraseñas, tokens ni llaves privadas):

- [ ] `hostname`, `whoami`, `pwd`
- [ ] `nginx -v`
- [ ] `systemctl status nginx --no-pager`
- [ ] `sudo nginx -t`
- [ ] `curl -I http://localhost` (código HTTP obtenido)
- [ ] Captura del navegador accediendo a la URL/IP pública
- [ ] URL o IP utilizada
- [ ] Archivo de configuración de Nginx (`nginx/muvautomation.conf`, ya versionado)
- [ ] Permisos del directorio publicado (`ls -la /opt/muvautomation`)
- [ ] Extracto de `access.log` (sin datos sensibles)
- [ ] Extracto de `error.log` (sin datos sensibles)

---

## 7. Diagnóstico del fallo

**No aplica todavía**: como el despliegue en servidor está pendiente (sección 6), no hay
un fallo real que diagnosticar en esta entrega. Se deja la tabla lista para completarse
si, al desplegar, algo no funciona como se espera:

| Prueba | Esperado | Obtenido | Evidencia | Causa probable |
|---|---|---|---|---|
| `curl localhost` | HTTP 200 | _(pendiente)_ | _(pendiente)_ | _(pendiente)_ |
| `nginx -t` | Syntax OK | _(pendiente)_ | _(pendiente)_ | _(pendiente)_ |
| Acceso público | Página visible | _(pendiente)_ | _(pendiente)_ | _(pendiente)_ |

Si el resultado real difiere del esperado (p. ej. `Connection refused`, error de sintaxis
en `nginx -t`, timeout de acceso público), se documentará aquí con captura y causa raíz
antes de la siguiente entrega.

---

## 8. Modelo de amenazas inicial

**DFD:** ver `diagrams/dfd-lab3.png` (sección 3 de este informe y `README.md`).

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
| H1 | Spoofing | `POST /alerts` | Un origen no autorizado puede enviar alertas haciéndose pasar por CrowdStrike Falcon; el endpoint no valida origen ni credenciales. | **Verificable hoy**: el `POST /alerts` ejecutado en la sección 5 fue aceptado (HTTP 201) sin ninguna credencial. | Exigir un token/API-key compartido o mTLS entre el generador de alertas y la API (Lab 4). |
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
de atacar) están completas a nivel de código y diseño: existe una API FastAPI funcional
con persistencia SQLite, una configuración de Nginx como reverse proxy, un DFD con su
límite de confianza y una tabla STRIDE que cubre las 6 categorías con al menos una
hipótesis, evidencia y mitigación propuesta cada una. La evidencia de ejecución local
(sección 5) confirma que el repositorio, el commit y la aplicación funcionan tal como se
documentan. Lo que queda pendiente para cerrar esta entrega es el despliegue real en el
servidor Ubuntu del laboratorio (sección 6) — sin el cual no se puede completar la
evidencia de servidor/Nginx ni la URL publicada — y, en fases posteriores, la
construcción de los componentes de clasificación/escalamiento y la corrección de las
limitaciones de seguridad ya documentadas (autenticación, TLS, hardening de Nginx),
que se abordarán en las Fases C a F.

---

## Anexo — Procedimiento de despliegue en Ubuntu (paso a paso)

Ver la sección final de la respuesta de esta conversación / `README.md` para el
procedimiento detallado y comentado de despliegue en el servidor Ubuntu del laboratorio.
