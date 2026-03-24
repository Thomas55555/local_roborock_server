import json
from pathlib import Path

from roborock_local_server.bundled_backend.shared import device_key_recovery


def test_device_key_cache_retries_saved_two_sample_recovery_on_load(
    tmp_path: Path,
    monkeypatch,
) -> None:
    resumed: list[str] = []

    def fake_maybe_recover_async(self, did: str) -> None:
        resumed.append(did)

    monkeypatch.setattr(
        device_key_recovery.DeviceKeyCache,
        "maybe_recover_async",
        fake_maybe_recover_async,
    )

    state_path = tmp_path / "device_key_state.json"
    state_path.write_text(
        json.dumps(
            {
                "devices": {
                    "1234567890123": {
                        "samples": [
                            {
                                "canonical": "foo=bar",
                                "signature_b64": "QUJD",
                            },
                            {
                                "canonical": "baz=qux",
                                "signature_b64": "REVG",
                            }
                        ],
                        "recovery": {
                            "state": "blocked",
                            "note": "Legacy state from before gmpy2 was required.",
                            "started_at": "2026-03-15T20:55:21.514097+00:00",
                        },
                    }
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    device_key_recovery.DeviceKeyCache(state_path)

    assert resumed == ["1234567890123"]
