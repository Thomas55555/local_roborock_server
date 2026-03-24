from pathlib import Path

from roborock_local_server.bundled_backend.shared.runtime_state import RuntimeState


def test_runtime_state_keeps_vacuum_connected_when_old_conn_closes_after_reconnect(tmp_path: Path) -> None:
    state = RuntimeState(log_dir=tmp_path, key_state_file=None)

    state.record_mqtt_connection(conn_id="old", client_ip="testclient", client_port=1883)
    state.record_mqtt_message(
        conn_id="old",
        direction="c2b",
        topic="rr/d/i/1103811971559/dd211305e2d4873b",
        payload_preview="{}",
    )

    state.record_mqtt_connection(conn_id="new", client_ip="testclient", client_port=1883)
    state.record_mqtt_message(
        conn_id="new",
        direction="c2b",
        topic="rr/d/i/1103811971559/dd211305e2d4873b",
        payload_preview="{}",
    )

    state.record_mqtt_disconnect(conn_id="old")

    snapshot = state.vacuum_snapshot()
    assert len(snapshot) == 1
    assert snapshot[0]["did"] == "1103811971559"
    assert snapshot[0]["connected"] is True
