import json
from pathlib import Path

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor


def test_restart_does_not_revert_known_vacuum_to_onboarding_wait_message(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "devices": [
                    {
                        "duid": "known-duid-1",
                        "name": "S7",
                        "model": "roborock.vacuum.a15",
                        "product_id": "product-1",
                        "local_key": "inventory-local-key",
                    }
                ]
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
                        "duid": "",
                        "name": "",
                        "model": "",
                        "product_id": "",
                        "localkey": "",
                        "local_key_source": "",
                        "device_mqtt_usr": "mqtt-user",
                        "updated_at": "2026-03-15T15:40:20.630821+00:00",
                        "last_nc_at": "",
                        "last_mqtt_seen_at": "2026-03-15T15:40:20.630800+00:00",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    paths.device_key_state_path.write_text(
        json.dumps(
            {
                "devices": {
                    "1103811971559": {
                        "pid": "roborock.vacuum.a15",
                    }
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()

    vacuums = supervisor._vacuums_payload()["vacuums"]

    assert len(vacuums) == 1
    assert vacuums[0]["name"] == "S7"
    assert vacuums[0]["onboarding"]["guidance"] == (
        "This vacuum has already connected to the local stack. "
        "Wait for it to reconnect after a server restart; onboarding does not need to be repeated."
    )
