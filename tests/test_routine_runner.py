import asyncio
import json
import logging
from pathlib import Path

from roborock_local_server.bundled_backend.shared.context import ServerContext
import roborock_local_server.bundled_backend.shared.routine_runner as routine_runner_module
from roborock_local_server.bundled_backend.shared.routine_runner import RoutineRunner, parse_scene_steps
from roborock.roborock_typing import RoborockCommand


def _test_context(tmp_path: Path) -> ServerContext:
    return ServerContext(
        api_host="api.example.com",
        mqtt_host="mqtt.example.com",
        wood_host="wood.example.com",
        region="us",
        localkey="local-key",
        duid="default-duid",
        mqtt_usr="mqtt-user",
        mqtt_passwd="mqtt-pass",
        mqtt_clientid="mqtt-client",
        mqtt_tls_port=8883,
        http_jsonl=tmp_path / "http.jsonl",
        mqtt_jsonl=tmp_path / "mqtt.jsonl",
        loggers={"api": logging.getLogger("test-routine-runner")},
    )


def _scene(*, scene_id: int, device_id: str, name: str) -> dict[str, object]:
    return {
        "id": scene_id,
        "name": name,
        "device_id": device_id,
        "param": (
            '{"action":{"items":[{"id":1,"type":"CMD","name":"Start",'
            '"finishDpIds":[130],"param":{"method":"do_scenes_app_start","params":[{"repeat":1}]}}]}}'
        ),
    }


def _scene_with_zone_tid(
    *,
    scene_id: int,
    device_id: str,
    name: str,
    tid: str,
    zid: int,
    range_coords: list[int] | None = None,
) -> dict[str, object]:
    zone_payload: dict[str, object] = {"zid": zid, "repeat": 1}
    if range_coords is not None:
        zone_payload["range"] = list(range_coords)
    return {
        "id": scene_id,
        "name": name,
        "device_id": device_id,
        "param": json.dumps(
            {
                "action": {
                    "items": [
                        {
                            "id": 1,
                            "type": "CMD",
                            "name": name,
                            "finishDpIds": [130],
                            "param": json.dumps(
                                {
                                    "method": "do_scenes_zones",
                                    "params": {
                                        "data": [
                                            {
                                                "tid": tid,
                                                "zones": [zone_payload],
                                                "fan_power": 108,
                                                "repeat": 1,
                                            }
                                        ]
                                    },
                                },
                                separators=(",", ":"),
                            ),
                        }
                    ]
                }
            },
            separators=(",", ":"),
        ),
    }


def test_repeating_scene_execute_requests_cancel(tmp_path: Path, monkeypatch) -> None:
    async def exercise() -> None:
        runner = RoutineRunner(_test_context(tmp_path))
        started = asyncio.Event()
        hold = asyncio.Event()
        stop_calls: list[tuple[str, int, str]] = []

        async def fake_run_scene(self: RoutineRunner, *, scene: dict[str, object], steps: list[object]) -> None:
            _ = self, scene, steps
            started.set()
            await hold.wait()

        async def fake_stop_scene(
            self: RoutineRunner,
            *,
            device_id: str,
            scene_id: int,
            scene_name: str,
        ) -> None:
            _ = self
            stop_calls.append((device_id, scene_id, scene_name))

        monkeypatch.setattr(RoutineRunner, "_run_scene", fake_run_scene)
        monkeypatch.setattr(RoutineRunner, "_stop_scene", fake_stop_scene)

        scene = _scene(scene_id=4491073, device_id="6HL2zfniaoYYV01CkVuhkO", name="After dinner")

        first = runner.start_scene(scene)
        assert first["accepted"] is True
        assert first["status"] == "started"

        await started.wait()

        second = runner.start_scene(scene)
        assert second["accepted"] is True
        assert second["status"] == "cancel_requested"

        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert stop_calls == [("6HL2zfniaoYYV01CkVuhkO", 4491073, "After dinner")]

    asyncio.run(exercise())


def test_different_scene_on_busy_device_stays_in_progress(tmp_path: Path, monkeypatch) -> None:
    async def exercise() -> None:
        runner = RoutineRunner(_test_context(tmp_path))
        started = asyncio.Event()
        hold = asyncio.Event()
        stop_calls: list[tuple[str, int, str]] = []

        async def fake_run_scene(self: RoutineRunner, *, scene: dict[str, object], steps: list[object]) -> None:
            _ = self, scene, steps
            started.set()
            await hold.wait()

        async def fake_stop_scene(
            self: RoutineRunner,
            *,
            device_id: str,
            scene_id: int,
            scene_name: str,
        ) -> None:
            _ = self
            stop_calls.append((device_id, scene_id, scene_name))

        monkeypatch.setattr(RoutineRunner, "_run_scene", fake_run_scene)
        monkeypatch.setattr(RoutineRunner, "_stop_scene", fake_stop_scene)

        first_scene = _scene(scene_id=4491073, device_id="6HL2zfniaoYYV01CkVuhkO", name="After dinner")
        second_scene = _scene(scene_id=4491074, device_id="6HL2zfniaoYYV01CkVuhkO", name="Kitchen")

        first = runner.start_scene(first_scene)
        assert first["accepted"] is True
        assert first["status"] == "started"

        await started.wait()

        second = runner.start_scene(second_scene)
        assert second["accepted"] is False
        assert second["status"] == "routine_in_progress"
        assert second["activeSceneId"] == 4491073
        assert second["activeSceneName"] == "After dinner"

        hold.set()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert stop_calls == []

    asyncio.run(exercise())


def test_run_scene_syncs_scene_tids_before_step_commands(tmp_path: Path, monkeypatch) -> None:
    async def exercise() -> None:
        inventory_path = tmp_path / "web_api_inventory.json"
        device_id = "6HL2zfniaoYYV01CkVuhkO"
        current_scene = _scene_with_zone_tid(
            scene_id=4491073,
            device_id=device_id,
            name="After dinner",
            tid="1773791700088",
            zid=8,
            range_coords=[32800, 22750, 34550, 25350],
        )
        inventory_path.write_text(
            json.dumps(
                {
                    "scenes": [
                        _scene_with_zone_tid(
                            scene_id=4491072,
                            device_id=device_id,
                            name="Night living room",
                            tid="1756774254605",
                            zid=5,
                        ),
                        current_scene,
                        _scene_with_zone_tid(
                            scene_id=4499999,
                            device_id="other-device",
                            name="Other device scene",
                            tid="999",
                            zid=1,
                        ),
                    ]
                }
            ),
            encoding="utf-8",
        )

        sent_commands: list[tuple[RoborockCommand, object]] = []

        class FakeRoutineClient:
            def __init__(self, context, device, logger) -> None:
                _ = context, device, logger

            async def connect(self) -> None:
                return None

            async def close(self) -> None:
                return None

            async def send_command(self, command, params=None):
                sent_commands.append((command, params))
                return ["ok"]

            async def wait_for_step_complete(self) -> None:
                return None

        monkeypatch.setattr(routine_runner_module, "_RoutineMqttClient", FakeRoutineClient)

        runner = RoutineRunner(_test_context(tmp_path))
        await runner._run_scene(scene=current_scene, steps=parse_scene_steps(current_scene))

        assert sent_commands[0] == (
            RoborockCommand.REUNION_SCENES,
            {"data": [{"tid": "1756774254605"}, {"tid": "1773791700088"}]},
        )
        assert sent_commands[1] == (RoborockCommand.SET_CUSTOM_MODE, [108])
        assert sent_commands[2] == (
            RoborockCommand.SET_SCENES_ZONES,
            {"data": [{"tid": "1773791700088", "zones": [{"zid": 8, "range": [32800, 22750, 34550, 25350]}]}]},
        )
        assert sent_commands[3] == (
            RoborockCommand.APP_ZONED_CLEAN,
            [{"zones": [{"zid": 8, "repeat": 1}], "repeat": 1}],
        )

    asyncio.run(exercise())
