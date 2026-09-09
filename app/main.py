"""MuvAutomation - Falcon Incident Lab API.

Prototipo del Lab 3 (Secure Product Challenge): recibe alertas ficticias de
CrowdStrike Falcon, permite consultarlas y registra las acciones realizadas.

Alcance intencional del Lab 3: HTTP sin autenticación ni cifrado. Este riesgo
se corrige en el Lab 4 (HTTPS + identidad + roles), no aqui.
"""
import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(__file__).resolve().parent / "alerts.db"
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

action_logger = logging.getLogger("actions")
action_logger.setLevel(logging.INFO)
_handler = logging.FileHandler(LOG_DIR / "actions.log", encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(message)s"))
action_logger.addHandler(_handler)

SEED_ALERTS = [
    {
        "severity": "high",
        "tactic": "Initial Access",
        "technique": "T1078 - Valid Accounts",
        "hostname": "WEB-LAB-01",
        "description": "Inicio de sesion desde ubicacion inusual (dato ficticio de laboratorio).",
    },
    {
        "severity": "medium",
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "hostname": "API-LAB-01",
        "description": "Escaneo de puertos detectado contra host de laboratorio (dato ficticio).",
    },
    {
        "severity": "critical",
        "tactic": "Exfiltration",
        "technique": "T1041 - Exfiltration Over C2 Channel",
        "hostname": "DB-LAB-01",
        "description": "Transferencia de datos anomala hacia destino externo (dato ficticio).",
    },
]


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                tactic TEXT NOT NULL,
                technique TEXT NOT NULL,
                hostname TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        if count == 0:
            for seed in SEED_ALERTS:
                conn.execute(
                    "INSERT INTO alerts (id, created_at, severity, tactic, technique, "
                    "hostname, description, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        datetime.now(timezone.utc).isoformat(),
                        seed["severity"],
                        seed["tactic"],
                        seed["technique"],
                        seed["hostname"],
                        seed["description"],
                        "new",
                    ),
                )
        conn.commit()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


class AlertIn(BaseModel):
    severity: str = Field(..., examples=["low", "medium", "high", "critical"])
    tactic: str = Field(..., examples=["Initial Access"])
    technique: str = Field(..., examples=["T1078 - Valid Accounts"])
    hostname: str = Field(..., examples=["WEB-LAB-01"])
    description: str


class AlertOut(AlertIn):
    id: str
    created_at: str
    status: str


app = FastAPI(
    title="MuvAutomation - Falcon Incident Lab API",
    description="Prototipo de laboratorio. Datos ficticios. Sin autenticacion (alcance Lab 3).",
    version="0.1.0",
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def log_action(request: Request, action: str, alert_id: Optional[str] = None) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "method": request.method,
        "path": request.url.path,
        "client_ip": request.client.host if request.client else None,
        "alert_id": alert_id,
    }
    action_logger.info(json.dumps(entry, ensure_ascii=False))


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    log_action(request, "view_root")
    return """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>MuvAutomation Falcon Lab</title></head>
<body>
  <h1>MuvAutomation - Falcon Incident Automation (LAB)</h1>
  <p>Environment: LAB</p>
  <p>Owner: Blue Team</p>
  <p>Datos ficticios. Endpoints: <code>POST /alerts</code>, <code>GET /alerts</code>,
     <code>GET /alerts/{id}</code></p>
</body>
</html>"""


@app.post("/alerts", response_model=AlertOut, status_code=201)
def create_alert(alert: AlertIn, request: Request):
    alert_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO alerts (id, created_at, severity, tactic, technique, "
            "hostname, description, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert_id,
                created_at,
                alert.severity,
                alert.tactic,
                alert.technique,
                alert.hostname,
                alert.description,
                "new",
            ),
        )
        conn.commit()
    log_action(request, "create_alert", alert_id)
    return AlertOut(id=alert_id, created_at=created_at, status="new", **alert.model_dump())


@app.get("/alerts", response_model=list[AlertOut])
def list_alerts(request: Request):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
    log_action(request, "list_alerts")
    return [AlertOut(**dict(row)) for row in rows]


@app.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: str, request: Request):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        log_action(request, "get_alert_not_found", alert_id)
        raise HTTPException(status_code=404, detail="Alert not found")
    log_action(request, "get_alert", alert_id)
    return AlertOut(**dict(row))
