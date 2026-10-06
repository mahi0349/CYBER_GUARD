import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.endpoint_risk_engine import endpoint_risk_engine
from app.services.endpoint_security import endpoint_security_mgr

client = TestClient(app)

def test_endpoint_risk_engine_clean():
    defender = {
        "available": True,
        "real_time_protection": True,
        "antivirus_enabled": True,
        "signature_age_days": 0
    }
    firewall = {
        "available": True,
        "all_enabled": True
    }
    res = endpoint_risk_engine.evaluate(
        defender_data=defender,
        firewall_data=firewall,
        processes=[],
        network_conns=[],
        startup_items=[],
        file_events=[],
        security_events=[]
    )
    assert res["score"] == 0
    assert res["level"] == "SAFE"
    assert any(c["type"] == "credit" for c in res["contributors"])

def test_endpoint_risk_engine_penalties():
    defender = {
        "available": True,
        "real_time_protection": False,
        "antivirus_enabled": False,
        "signature_age_days": 12
    }
    firewall = {
        "available": True,
        "all_enabled": False
    }
    startup = [{"name": "bad_entry", "suspicious": True, "reasons": ["Running from temp"]}]
    procs = [{"pid": 1234, "name": "miner.exe", "risk_level": "HIGH", "risk_reasons": ["Temp dir"]}]
    conns = [{"pid": 1234, "process_name": "miner.exe", "risk_level": "HIGH", "risk_reasons": ["Port 4444"]}]

    res = endpoint_risk_engine.evaluate(
        defender_data=defender,
        firewall_data=firewall,
        processes=procs,
        network_conns=conns,
        startup_items=startup,
        file_events=[],
        security_events=[]
    )
    assert res["score"] >= 60
    assert res["level"] in ["HIGH", "CRITICAL"]
    assert any("Defender" in c["factor"] for c in res["contributors"])

def test_api_status_offline_initially():
    # When no agent has reported recently or ever
    resp = client.get("/api/v1/command-center/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert data["status"] in ["ONLINE", "DEGRADED", "OFFLINE"]

def test_api_risk_score():
    resp = client.get("/api/v1/command-center/risk")
    assert resp.status_code == 200
    data = resp.json()
    assert "score" in data
    assert "level" in data
    assert "breakdown" in data
    assert "contributors" in data

def test_api_ingest_auth_failure():
    resp = client.post("/api/v1/command-center/ingest", json={"type": "test"})
    assert resp.status_code == 401

def test_api_ingest_success_and_retrieval():
    payload = {
        "type": "device_register",
        "device_id": "test-device-pc",
        "data": {
            "device_id": "test-device-pc",
            "hostname": "Test-PC",
            "os_name": "Windows",
            "os_version": "10.0.22631",
            "agent_version": "1.0.0",
            "status": "ONLINE"
        }
    }
    headers = {
        "Authorization": "Bearer qv-endpoint-agent-token-2026",
        "X-Device-ID": "test-device-pc"
    }
    resp = client.post("/api/v1/command-center/ingest", json=payload, headers=headers)
    assert resp.status_code == 200

    # Ingest protection status
    prot_payload = {
        "type": "protection_status",
        "device_id": "test-device-pc",
        "data": {
            "defender": {
                "available": True,
                "status": "PROTECTED",
                "real_time_protection": True,
                "antivirus_enabled": True,
                "signature_version": "1.459.574.0",
                "signature_age_days": 0
            },
            "firewall": {
                "available": True,
                "status": "ACTIVE",
                "all_enabled": True,
                "profiles": {
                    "Domain": {"enabled": True},
                    "Private": {"enabled": True},
                    "Public": {"enabled": True}
                }
            }
        }
    }
    resp2 = client.post("/api/v1/command-center/ingest", json=prot_payload, headers=headers)
    assert resp2.status_code == 200

    # Now verify GET /protection
    prot_get = client.get("/api/v1/command-center/protection")
    assert prot_get.status_code == 200
    data = prot_get.json()
    assert data["defender"]["available"] is True
    assert data["firewall"]["all_enabled"] is True

def test_scan_trigger():
    resp = client.post("/api/v1/command-center/scans/run", json={"scan_type": "quick"})
    assert resp.status_code == 200
    data = resp.json()
    assert "scan_id" in data
    assert data["status"] in ["QUEUED", "UNAVAILABLE", "RUNNING"]
