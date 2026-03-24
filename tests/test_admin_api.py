import json
import sys
import types
from datetime import datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor, resolve_route


def _scene_zone_step(
    *,
    step_id: int,
    device_id: str,
    tid: str,
    zid: int,
    repeat: int,
    fan_power: int,
    water_box_mode: int,
    range_coords: list[int] | None = None,
) -> dict[str, object]:
    zone_payload: dict[str, object] = {"zid": zid, "repeat": repeat}
    if range_coords is not None:
        zone_payload["range"] = list(range_coords)
    return {
        "id": step_id,
        "name": "",
        "type": "CMD",
        "entityId": device_id,
        "param": json.dumps(
            {
                "id": step_id,
                "method": "do_scenes_zones",
                "params": {
                    "data": [
                        {
                            "tid": tid,
                            "zones": [zone_payload],
                            "map_flag": 0,
                            "fan_power": fan_power,
                            "water_box_mode": water_box_mode,
                            "repeat": repeat,
                        }
                    ],
                    "source": 101,
                },
            },
            separators=(",", ":"),
        ),
        "finishDpIds": [130],
    }


def _after_dinner_param_payload(device_id: str, *, include_ranges: bool) -> dict[str, object]:
    return {
        "triggers": [],
        "action": {
            "type": "S",
            "items": [
                _scene_zone_step(
                    step_id=1,
                    device_id=device_id,
                    tid="1773791700088",
                    zid=8,
                    repeat=1,
                    fan_power=108,
                    water_box_mode=200,
                    range_coords=[32800, 22750, 34550, 25350] if include_ranges else None,
                ),
                _scene_zone_step(
                    step_id=2,
                    device_id=device_id,
                    tid="1773791720547",
                    zid=9,
                    repeat=2,
                    fan_power=104,
                    water_box_mode=202,
                    range_coords=[32550, 22650, 34550, 25200] if include_ranges else None,
                ),
            ],
        },
        "matchType": "NONE",
    }


def _write_scene_zone_trace(mqtt_jsonl_path: Path) -> None:
    mqtt_jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    entries = [
        {
            "decoded_messages": [
                {
                    "response_to": {
                        "request_method": "set_scenes_zones",
                        "request_params": {
                            "data": [
                                {
                                    "zones": [
                                        {
                                            "range": [32800, 22750, 34550, 25350],
                                        }
                                    ]
                                }
                            ]
                        },
                        "result": [
                            {
                                "tid": "1773791700088",
                                "zones": [{"zid": 8}],
                            }
                        ],
                    }
                }
            ]
        },
        {
            "decoded_messages": [
                {
                    "response_to": {
                        "request_method": "set_scenes_zones",
                        "request_params": {
                            "data": [
                                {
                                    "zones": [
                                        {
                                            "range": [32550, 22650, 34550, 25200],
                                        }
                                    ]
                                }
                            ]
                        },
                        "result": [
                            {
                                "tid": "1773791720547",
                                "zones": [{"zid": 9}],
                            }
                        ],
                    }
                }
            ]
        },
    ]
    mqtt_jsonl_path.write_text(
        "\n".join(json.dumps(entry, separators=(",", ":")) for entry in entries) + "\n",
        encoding="utf-8",
    )


def test_admin_login_and_status_flow(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)

    client = TestClient(supervisor.app)

    login_page = client.get("/admin")
    assert login_page.status_code == 200
    assert "Sign in to manage the stack." in login_page.text

    unauthenticated_status = client.get("/admin/api/status")
    assert unauthenticated_status.status_code == 401

    bad_login = client.post("/admin/api/login", json={"password": "wrong"})
    assert bad_login.status_code == 401

    good_login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert good_login.status_code == 200
    assert supervisor.session_manager.cookie_name in good_login.cookies

    status = client.get("/admin/api/status")
    assert status.status_code == 200
    payload = status.json()
    support_urls = [item["url"] for item in payload["support"]["links"]]
    assert support_urls == [
        "https://buymeacoffee.com/lashl",
        "https://paypal.me/LLashley304",
        "https://us.roborock.com/discount/RRSAP202602071713342D18X?redirect=%2Fpages%2Froborock-store%3Fuuid%3DEQe6p1jdZczHEN4Q0nbsG9sZRm0RK1gW5eSM%252FCzcW4Q%253D",
        "https://roborock.pxf.io/B0VYV9",
        "https://amzn.to/4bGfG6B",
    ]
    assert payload["health"]["services"]
    assert payload["pairing"]["active"] is False
    assert payload["mitm_intercept"]["running"] is False

    vacuums = client.get("/admin/api/vacuums")
    assert vacuums.status_code == 200
    assert vacuums.json()["vacuums"] == []

    dashboard_page = client.get("/admin")
    assert dashboard_page.status_code == 200
    assert "Cloud Import" in dashboard_page.text
    assert "Pair Device" in dashboard_page.text
    assert "iPhone MITM Intercept" in dashboard_page.text
    assert "Open WireGuard QR" in dashboard_page.text
    assert "Buy Me a Coffee" in dashboard_page.text
    assert "PayPal" in dashboard_page.text
    assert "5% Off Roborock Store" in dashboard_page.text
    assert "Roborock Affiliate" in dashboard_page.text
    assert "Amazon Affiliate" in dashboard_page.text

    logout = client.post("/admin/api/logout")
    assert logout.status_code == 200

    status_after_logout = client.get("/admin/api/status")
    assert status_after_logout.status_code == 401


def test_core_only_mode_disables_standalone_admin_routes(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths, enable_standalone_admin=False)

    client = TestClient(supervisor.app)

    admin_page = client.get("/admin")
    assert admin_page.status_code == 404

    ui_health = client.get("/ui/api/health")
    assert ui_health.status_code == 200

    region_response = client.get("/region")
    assert region_response.status_code == 200


def test_admin_mitm_start_stop_endpoints_removed(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)

    client = TestClient(supervisor.app)
    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    status_before = client.get("/admin/api/mitm/status")
    assert status_before.status_code == 200
    assert status_before.json()["mitm_intercept"]["running"] is False

    start = client.post("/admin/api/mitm/start")
    assert start.status_code == 410
    assert "managed externally" in start.json()["error"]

    stop = client.post("/admin/api/mitm/stop")
    assert stop.status_code == 410
    assert "managed externally" in stop.json()["error"]

def test_admin_mitm_log_tail_and_logs_page(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)

    log_path = tmp_path / "mitm_intercept.log"
    log_path.write_text(
        "\n".join(
            [
                "WireGuard mode active",
                "Scan QR code in WireGuard app",
                "Web UI: http://127.0.0.1:8081/",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    supervisor.mitm_intercept._log_path = log_path  # type: ignore[attr-defined]

    client = TestClient(supervisor.app)
    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    logs_page = client.get("/admin/mitm/logs")
    assert logs_page.status_code == 200
    assert "MITM Logs" in logs_page.text

    tail = client.get("/admin/api/mitm/log-tail?lines=50")
    assert tail.status_code == 200
    payload = tail.json()
    assert payload["ok"] is True
    assert "WireGuard mode active" in payload["lines"]
    assert any("Scan QR code" in line for line in payload["setup_hints"])
    assert "http://127.0.0.1:8081/" in payload["detected_urls"]


def test_admin_mitm_wireguard_config_endpoint(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)

    wireguard_conf = tmp_path / "wireguard-client.conf"
    wireguard_conf.write_text(
        "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n",
        encoding="utf-8",
    )
    log_path = tmp_path / "mitm_intercept.log"
    log_path.write_text(
        f"Client config written to {wireguard_conf}\n",
        encoding="utf-8",
    )
    supervisor.mitm_intercept._log_path = log_path  # type: ignore[attr-defined]
    client = TestClient(supervisor.app)
    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    response = client.get("/admin/api/mitm/wireguard-config")
    assert response.status_code == 200
    assert "[Interface]" in response.text
    assert "PrivateKey = abc" in response.text


def test_admin_mitm_wireguard_config_rewrites_docker_endpoint_from_log_block(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)

    log_path = tmp_path / "mitm_intercept.log"
    log_path.write_text(
        "\n".join(
            [
                "------------------------------------------------------------",
                "[Interface]",
                "PrivateKey = client-key",
                "Address = 10.0.0.1/32",
                "DNS = 10.0.0.53",
                "[Peer]",
                "PublicKey = server-key",
                "AllowedIPs = 0.0.0.0/0",
                "Endpoint = 172.19.0.2:51820",
                "------------------------------------------------------------",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    supervisor.mitm_intercept._log_path = log_path  # type: ignore[attr-defined]
    supervisor.mitm_intercept._wireguard_endpoint_host = "192.168.1.42"  # type: ignore[attr-defined]
    client = TestClient(supervisor.app)
    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    response = client.get("/admin/api/mitm/wireguard-config?endpoint_host=192.168.1.42")
    assert response.status_code == 200
    assert "PrivateKey = client-key" in response.text
    assert "PublicKey = server-key" in response.text
    assert "Endpoint = 192.168.1.42:51820" in response.text
    assert "Endpoint = 172.19.0.2:51820" not in response.text


def test_admin_mitm_wireguard_qr_endpoint_returns_svg(tmp_path: Path, monkeypatch) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)

    log_path = tmp_path / "mitm_intercept.log"
    log_path.write_text(
        "\n".join(
            [
                "------------------------------------------------------------",
                "[Interface]",
                "PrivateKey = client-key",
                "Address = 10.0.0.1/32",
                "DNS = 10.0.0.53",
                "[Peer]",
                "PublicKey = server-key",
                "AllowedIPs = 0.0.0.0/0",
                "Endpoint = 172.19.0.2:51820",
                "------------------------------------------------------------",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    supervisor.mitm_intercept._log_path = log_path  # type: ignore[attr-defined]
    class _DummyImage:
        def save(self, buffer) -> None:
            buffer.write(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>")

    class _DummyQrCode:
        def __init__(self, **kwargs) -> None:
            _ = kwargs
            self._payload = ""

        def add_data(self, value: str) -> None:
            self._payload = value

        def make(self, *, fit: bool = True) -> None:
            _ = fit

        def make_image(self, *, image_factory=None):
            _ = image_factory
            return _DummyImage()

    fake_qrcode = types.ModuleType("qrcode")
    fake_qrcode.QRCode = _DummyQrCode
    fake_qrcode.__path__ = []  # type: ignore[attr-defined]
    fake_qrcode_image = types.ModuleType("qrcode.image")
    fake_qrcode_image.__path__ = []  # type: ignore[attr-defined]
    fake_qrcode_svg = types.ModuleType("qrcode.image.svg")
    fake_qrcode_svg.SvgImage = object
    monkeypatch.setitem(sys.modules, "qrcode", fake_qrcode)
    monkeypatch.setitem(sys.modules, "qrcode.image", fake_qrcode_image)
    monkeypatch.setitem(sys.modules, "qrcode.image.svg", fake_qrcode_svg)

    client = TestClient(supervisor.app)
    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    response = client.get("/admin/api/mitm/wireguard-qr?endpoint_host=192.168.1.42")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in response.text


def test_ui_api_health_and_vacuums_return_runtime_payload_without_auth(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.inventory_path.parent.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "devices": [
                    {
                        "duid": "inventory-s7-duid",
                        "name": "S7",
                        "model": "roborock.vacuum.a15",
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.runtime_state.record_mqtt_connection(
        conn_id="ui-conn-1",
        client_ip="192.168.1.50",
        client_port=1883,
    )
    supervisor.runtime_state.record_mqtt_message(
        conn_id="ui-conn-1",
        direction="c2b",
        topic="rr/m/i/test-user/test-client/inventory-s7-duid",
        payload_preview="{}",
    )

    client = TestClient(supervisor.app)

    health = client.get("/ui/api/health")
    assert health.status_code == 200
    health_payload = health.json()
    assert health_payload["active_mqtt_connections"] == 1
    assert [vac["duid"] for vac in health_payload["connected_vacuums"]] == ["inventory-s7-duid"]

    vacuums = client.get("/ui/api/vacuums")
    assert vacuums.status_code == 200
    vacuums_payload = vacuums.json()
    assert vacuums_payload["required_onboarding_steps"] == ["region", "nc_prepare"]
    assert vacuums_payload["step_labels"]["region"] == "Region"
    s7 = next(vac for vac in vacuums_payload["vacuums"] if vac["duid"] == "inventory-s7-duid")
    assert s7["name"] == "S7"
    assert s7["connected"] is True


def test_admin_pair_device_flow_tracks_region_nc_public_key_and_connected(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)

    client = TestClient(supervisor.app)
    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    start_pairing = client.post("/admin/api/pair-device")
    assert start_pairing.status_code == 200
    pairing_payload = start_pairing.json()["pairing"]
    assert pairing_payload["active"] is True
    assert pairing_payload["message"] == "Waiting for device to pair - please use the onboarding script"
    assert pairing_payload["checks"] == {
        "region": False,
        "nc": False,
        "public_key": False,
        "connected": False,
    }
    public_key_step = next(step for step in pairing_payload["steps"] if step["key"] == "public_key")
    assert public_key_step["detail"] == "(0 samples)"

    region_response = client.get("/region")
    assert region_response.status_code == 200
    pairing_after_region = client.get("/admin/api/status").json()["pairing"]
    assert pairing_after_region["checks"]["region"] is True
    assert pairing_after_region["checks"]["nc"] is False

    did = "1234567890123"
    nc_response = client.get(f"/api/v1/nc/prepare?did={did}")
    assert nc_response.status_code == 200
    pairing_after_nc = client.get("/admin/api/status").json()["pairing"]
    assert pairing_after_nc["checks"]["nc"] is True
    assert pairing_after_nc["target"]["did"] == did

    started_at = datetime.fromisoformat(pairing_payload["started_at"])
    recovered_at = (started_at + timedelta(seconds=1)).isoformat()
    paths.device_key_state_path.write_text(
        json.dumps(
            {
                "devices": {
                    did: {
                        "samples": [
                            {
                                "canonical": "foo=bar",
                                "signature_b64": "QUJD",
                            }
                        ],
                        "modulus_hex": "abcd",
                        "recovery": {
                            "state": "recovered",
                            "note": "Public key is available.",
                            "finished_at": recovered_at,
                        },
                    }
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    pairing_after_key = client.get("/admin/api/status").json()["pairing"]
    assert pairing_after_key["checks"]["public_key"] is True
    public_key_step = next(step for step in pairing_after_key["steps"] if step["key"] == "public_key")
    assert public_key_step["detail"] == "(1 sample)"

    supervisor.runtime_state.record_mqtt_connection(conn_id="pair-1", client_ip="testclient", client_port=1883)
    supervisor.runtime_state.record_mqtt_message(
        conn_id="pair-1",
        direction="c2b",
        topic=f"rr/d/i/{did}/mqtt-user",
        payload_preview="{}",
    )

    pairing_after_connect = client.get("/admin/api/status").json()["pairing"]
    assert pairing_after_connect["checks"] == {
        "region": True,
        "nc": True,
        "public_key": True,
        "connected": True,
    }
    assert pairing_after_connect["complete"] is True

    supervisor.runtime_state.record_mqtt_disconnect(conn_id="pair-1")
    pairing_after_disconnect = client.get("/admin/api/status").json()["pairing"]
    assert pairing_after_disconnect["checks"]["connected"] is False
    assert pairing_after_disconnect["complete"] is False


def test_admin_status_health_deduplicates_split_runtime_and_inventory_entries(tmp_path: Path) -> None:
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
                        "duid": "inventory-s7-duid",
                        "name": "S7",
                        "model": "roborock.vacuum.a15",
                        "product_id": "product-s7",
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

    client = TestClient(supervisor.app)
    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    raw_runtime_health = supervisor.runtime_state.health_snapshot()
    assert len(raw_runtime_health["all_vacuums"]) == 2

    status_payload = client.get("/admin/api/status").json()
    health_vacuums = status_payload["health"]["all_vacuums"]
    assert len(health_vacuums) == 1
    assert health_vacuums[0]["name"] == "S7"
    assert health_vacuums[0]["did"] == "1103811971559"
    assert health_vacuums[0]["duid"] == "inventory-s7-duid"


def test_admin_status_health_deduplicates_split_same_model_entries_via_persisted_did_mapping(tmp_path: Path) -> None:
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
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "local_key": "local-key-a",
                    },
                    {
                        "duid": "cloud-q7-b",
                        "name": "Q7 Downstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-b",
                        "local_key": "local-key-b",
                    },
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
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "localkey": "local-key-a",
                        "local_key_source": "inventory",
                        "device_mqtt_usr": "mqtt-user-a",
                        "updated_at": "2026-03-16T00:22:31.225097+00:00",
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
    supervisor.runtime_state.record_mqtt_connection(conn_id="dup-1", client_ip="testclient", client_port=1883)
    supervisor.runtime_state.record_mqtt_message(
        conn_id="dup-1",
        direction="c2b",
        topic="rr/d/i/1103821560705/mqtt-user-a",
        payload_preview="{}",
    )

    client = TestClient(supervisor.app)
    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    raw_runtime_health = supervisor.runtime_state.health_snapshot()
    assert len(raw_runtime_health["all_vacuums"]) == 3

    status_payload = client.get("/admin/api/status").json()
    health_vacuums = status_payload["health"]["all_vacuums"]
    assert len(health_vacuums) == 2
    assert [vac["duid"] for vac in health_vacuums] == ["cloud-q7-b", "cloud-q7-a"]

    matched = next(vac for vac in health_vacuums if vac["duid"] == "cloud-q7-a")
    assert matched["did"] == "1103821560705"
    assert matched["linked_via"] == "did"


def test_scene_update_routes_persist_name_and_zone_ranges(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    device_id = "6HL2zfniaoYYV01CkVuhkO"

    paths.inventory_path.parent.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1233716, "name": "My Home"},
                "devices": [
                    {
                        "duid": device_id,
                        "name": "Qrevo MaxV",
                        "model": "roborock.vacuum.a87",
                    }
                ],
                "scenes": [
                    {
                        "id": 4491073,
                        "name": "Old after dinner",
                        "device_id": device_id,
                        "device_name": "Qrevo MaxV",
                        "enabled": True,
                        "type": "WORKFLOW",
                        "param": json.dumps(_after_dinner_param_payload(device_id, include_ranges=False), separators=(",", ":")),
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _write_scene_zone_trace(paths.mqtt_jsonl_path)

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    client = TestClient(supervisor.app)

    rename_response = client.put("/user/scene/4491073/name", data={"name": "After dinner"})
    assert rename_response.status_code == 200
    assert rename_response.json()["data"]["name"] == "After dinner"

    update_response = client.put("/user/scene/4491073/param", json=_after_dinner_param_payload(device_id, include_ranges=False))
    assert update_response.status_code == 200

    stored_inventory = json.loads(paths.inventory_path.read_text(encoding="utf-8"))
    scene = next(scene for scene in stored_inventory["scenes"] if scene["id"] == 4491073)
    assert scene["name"] == "After dinner"

    outer = json.loads(scene["param"])
    first_item = outer["action"]["items"][0]
    second_item = outer["action"]["items"][1]
    first_step = json.loads(first_item["param"])
    second_step = json.loads(second_item["param"])
    assert first_step["params"]["data"][0]["zones"][0]["range"] == [32800, 22750, 34550, 25350]
    assert second_step["params"]["data"][0]["zones"][0]["range"] == [32550, 22650, 34550, 25200]


def test_execute_scene_hydrates_missing_zone_ranges_from_mqtt(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    device_id = "6HL2zfniaoYYV01CkVuhkO"

    paths.inventory_path.parent.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1233716, "name": "My Home"},
                "devices": [
                    {
                        "duid": device_id,
                        "name": "Qrevo MaxV",
                        "model": "roborock.vacuum.a87",
                    }
                ],
                "scenes": [
                    {
                        "id": 4491073,
                        "name": "After dinner",
                        "device_id": device_id,
                        "device_name": "Qrevo MaxV",
                        "enabled": True,
                        "type": "WORKFLOW",
                        "param": json.dumps(_after_dinner_param_payload(device_id, include_ranges=False), separators=(",", ":")),
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _write_scene_zone_trace(paths.mqtt_jsonl_path)

    captured_scene: dict[str, object] = {}

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.context._routine_runner = type(
        "DummyRoutineRunner",
        (),
        {
            "start_scene": lambda self, scene: (
                captured_scene.clear(),
                captured_scene.update(scene),
                {"accepted": True, "status": "started"},
            )[-1]
        },
    )()
    route_name, response_payload = resolve_route(
        rules=supervisor.endpoint_rules,
        context=supervisor.context,
        clean_path="/user/scene/4491073/execute",
        query_params={},
        body_params={},
        method="POST",
    )
    assert route_name == "execute_scene"
    assert response_payload["data"]["status"] == "started"

    executed_outer = json.loads(str(captured_scene["param"]))
    executed_step = json.loads(executed_outer["action"]["items"][0]["param"])
    assert executed_step["params"]["data"][0]["zones"][0]["range"] == [32800, 22750, 34550, 25350]

    stored_inventory = json.loads(paths.inventory_path.read_text(encoding="utf-8"))
    scene = next(scene for scene in stored_inventory["scenes"] if scene["id"] == 4491073)
    persisted_outer = json.loads(scene["param"])
    persisted_step = json.loads(persisted_outer["action"]["items"][0]["param"])
    assert persisted_step["params"]["data"][0]["zones"][0]["range"] == [32800, 22750, 34550, 25350]
