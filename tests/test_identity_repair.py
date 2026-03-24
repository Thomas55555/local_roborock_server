import json
from pathlib import Path

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import repair_runtime_identities


def test_repair_runtime_identities_merges_existing_split_record(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.device_key_state_path.write_text('{"devices":{}}\n', encoding="utf-8")
    paths.inventory_path.write_text(
        json.dumps(
            {
                "devices": [
                    {
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "local_key": "local-key-a",
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
                        "did": "1103821560705",
                        "duid": "",
                        "name": "",
                        "model": "",
                        "product_id": "",
                        "localkey": "",
                        "local_key_source": "",
                        "device_mqtt_usr": "mqtt-user-a",
                        "updated_at": "2026-03-16T00:22:31.225097+00:00",
                        "last_nc_at": "",
                        "last_mqtt_seen_at": "2026-03-16T00:22:31.225063+00:00",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    exit_code = repair_runtime_identities(
        config_file=config_file,
        links=["1103821560705=cloud-q7-a"],
    )

    assert exit_code == 0
    repaired = json.loads(paths.runtime_credentials_path.read_text(encoding="utf-8"))
    devices = repaired["devices"]
    assert len(devices) == 1
    assert devices[0]["did"] == "1103821560705"
    assert devices[0]["duid"] == "cloud-q7-a"
    assert devices[0]["name"] == "Q7 Upstairs"
    assert devices[0]["localkey"] == "local-key-a"
