import json
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor


def test_home_data_marks_runtime_connected_device_online_via_runtime_credentials(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1233716, "name": "My Home"},
                "devices": [
                    {
                        "duid": "1OVJHS7cL6XxkYkoOGr2Hw",
                        "name": "S7",
                        "model": "roborock.vacuum.a15",
                        "product_id": "1YYW18rpgyAJTISwb1NM91",
                        "local_key": "GTWJJAA457z43dur",
                        "online": False,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    paths.runtime_credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103811971559",
                        "duid": "1OVJHS7cL6XxkYkoOGr2Hw",
                        "name": "S7",
                        "model": "roborock.vacuum.a15",
                        "product_id": "1YYW18rpgyAJTISwb1NM91",
                        "localkey": "GTWJJAA457z43dur",
                        "local_key_source": "inventory_cloud",
                        "device_mqtt_usr": "dd211305e2d4873b",
                        "updated_at": "2026-03-17T22:50:00+00:00",
                        "last_nc_at": "",
                        "last_mqtt_seen_at": "",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()
    supervisor.runtime_state.record_mqtt_connection(conn_id="s7-live", client_ip="testclient", client_port=1883)
    supervisor.runtime_state.record_mqtt_message(
        conn_id="s7-live",
        direction="c2b",
        topic="rr/d/i/1103811971559/dd211305e2d4873b",
        payload_preview="{}",
    )

    client = TestClient(supervisor.app)
    response = client.get("/v3/user/homes/1233716")
    assert response.status_code == 200

    home_data = response.json()["data"]
    s7 = next(device for device in home_data["devices"] if device["duid"] == "1OVJHS7cL6XxkYkoOGr2Hw")
    assert s7["online"] is True
