"""Pruebas de la Parte 2: controles de seguridad y motores de clasificacion/escalamiento.

Ejecutar desde la raiz del repositorio:  python -m pytest -q
"""
import io
import json
import os
import urllib.error

import pytest

API_KEY = "clave-emisor-de-prueba-123456"
KEY_ANA = "clave-ana-respondedora-123456"
KEY_JUAN = "clave-juan-lector-1234567890"
os.environ["MUV_API_KEY"] = API_KEY
os.environ["MUV_ANALYSTS"] = f"ana:respondedor:{KEY_ANA};juan:lector:{KEY_JUAN}"
os.environ.pop("ABUSEIPDB_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import enrichment, main  # noqa: E402

EMISOR = {"X-API-Key": API_KEY}
ANA = {"X-Analyst-Key": KEY_ANA}
JUAN = {"X-Analyst-Key": KEY_JUAN}
ALERT = {
    "severity": "high",
    "tactic": "Initial Access",
    "technique": "T1078 - Valid Accounts",
    "hostname": "WEB-LAB-01",
    "description": "Prueba automatizada (dato ficticio)",
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.db")
    with TestClient(main.app) as c:
        yield c


def create(client, **overrides):
    r = client.post("/alerts", json={**ALERT, **overrides}, headers=EMISOR)
    assert r.status_code == 201, r.text
    return r.json()["id"]


# --- Superficie expuesta ------------------------------------------------------


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_disabled(client, path):
    assert client.get(path).status_code == 404


def test_root_is_public(client):
    assert client.get("/").status_code == 200


# --- Autenticacion del emisor (H1) ----------------------------------------------


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "incorrecta"}, ANA])
def test_post_requires_emitter_key(client, headers):
    assert client.post("/alerts", json=ALERT, headers=headers).status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [
        {"severity": "xxx"},
        {"hostname": "a b<script>"},
        {"description": "x" * 1001},
        {"status": "closed"},
        {"source_ip": "no-es-una-ip"},
    ],
)
def test_post_validates_schema(client, overrides):
    r = client.post("/alerts", json={**ALERT, **overrides}, headers=EMISOR)
    assert r.status_code == 422


# --- Autenticacion y roles del analista (H3, H4, H6) ------------------------------


def test_read_requires_analyst(client):
    assert client.get("/alerts").status_code == 401
    assert client.get("/alerts", headers=EMISOR).status_code == 401
    assert client.get("/alerts", headers=JUAN).status_code == 200


def test_reader_cannot_escalate_or_close(client):
    alert_id = create(client)
    for action in ("escalate", "close"):
        r = client.post(f"/alerts/{alert_id}/actions", json={"action": action}, headers=JUAN)
        assert r.status_code == 403
    r = client.post(f"/alerts/{alert_id}/actions", json={"action": "acknowledge"}, headers=JUAN)
    assert r.status_code == 201


def test_responder_actions_are_attributed(client):
    alert_id = create(client)
    r = client.post(
        f"/alerts/{alert_id}/actions", json={"action": "close", "note": "falso positivo"}, headers=ANA
    )
    assert r.status_code == 201
    detail = client.get(f"/alerts/{alert_id}", headers=ANA).json()
    assert detail["status"] == "closed"
    assert detail["actions"][-1] == {**detail["actions"][-1], "analyst": "ana", "role": "respondedor"}
    # Una alerta cerrada solo admite comentarios.
    r = client.post(f"/alerts/{alert_id}/actions", json={"action": "escalate"}, headers=ANA)
    assert r.status_code == 409


# --- Motor de Clasificacion y Enriquecimiento + Escalamiento --------------------


def test_alert_is_classified_with_mitre(client):
    alert_id = create(client)
    alert = client.get(f"/alerts/{alert_id}", headers=JUAN).json()
    assert alert["risk_score"] == 60
    assert alert["classification"] == "media"
    assert alert["status"] == "classified"
    mitre = alert["enrichment"]["mitre"]
    assert mitre["technique_id"] == "T1078"
    assert mitre["name"] == "Valid Accounts"
    assert mitre["tactic_matches"] is True
    assert alert["enrichment"]["abuseipdb"]["status"] == "skipped_no_ip"


def test_critical_alert_is_auto_escalated(client):
    alert_id = create(
        client, severity="critical", tactic="Exfiltration", technique="T1041 - Exfiltration Over C2 Channel"
    )
    alert = client.get(f"/alerts/{alert_id}", headers=JUAN).json()
    assert alert["risk_score"] == 90
    assert alert["status"] == "escalated"


def test_tactic_mismatch_is_flagged(client):
    alert_id = create(client, tactic="Impact")
    flags = client.get(f"/alerts/{alert_id}", headers=JUAN).json()["enrichment"]["flags"]
    assert "tactic_mismatch" in flags


def test_filters(client):
    create(client, severity="low")
    create(client, severity="critical", tactic="Impact", technique="T1485 - Data Destruction")
    r = client.get("/alerts", params={"severity": "critical"}, headers=JUAN).json()
    assert r and all(a["severity"] == "critical" for a in r)
    r = client.get("/alerts", params={"min_score": 70}, headers=JUAN).json()
    assert r and all(a["risk_score"] >= 70 for a in r)
    assert client.get("/alerts", params={"limit": 1000}, headers=JUAN).status_code == 422


# --- AbuseIPDB: integracion externa controlada --------------------------------


def test_abuseipdb_never_queries_private_ips(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", pytest.fail)
    assert enrichment.abuseipdb_check("192.168.61.1")["status"] == "skipped_not_public"


def test_abuseipdb_without_key_is_skipped():
    assert enrichment.abuseipdb_check("8.8.8.8")["status"] == "skipped_no_key"


def _fake_response(payload):
    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return lambda req, timeout: Resp(json.dumps(payload).encode())


def test_abuseipdb_ok_raises_score(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    enrichment._abuse_cache.clear()
    monkeypatch.setattr(
        enrichment.urllib.request,
        "urlopen",
        _fake_response({"data": {"abuseConfidenceScore": 100, "totalReports": 50, "countryCode": "NL"}}),
    )
    score, _, enriched = enrichment.classify({**ALERT, "source_ip": "203.0.114.10"})
    assert score == 80
    assert "ip_maliciosa" in enriched["flags"]


def test_abuseipdb_rejects_invalid_response(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    enrichment._abuse_cache.clear()
    monkeypatch.setattr(
        enrichment.urllib.request,
        "urlopen",
        _fake_response({"data": {"abuseConfidenceScore": 999, "totalReports": 1}}),
    )
    assert enrichment.abuseipdb_check("203.0.114.11") == {"status": "error", "reason": "invalid_response"}


def test_abuseipdb_failure_does_not_block_classification(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    enrichment._abuse_cache.clear()

    def boom(req, timeout):
        raise urllib.error.URLError("sin red")

    monkeypatch.setattr(enrichment.urllib.request, "urlopen", boom)
    score, classification, enriched = enrichment.classify({**ALERT, "source_ip": "203.0.114.12"})
    assert (score, classification) == (60, "media")
    assert enriched["abuseipdb"]["status"] == "error"
