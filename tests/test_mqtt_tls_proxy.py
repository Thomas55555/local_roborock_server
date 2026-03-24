import logging
import threading
import time

from roborock_local_server.backend import MqttTlsProxy


class _FakeSourceSocket:
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def recv(self, _size: int) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def close(self) -> None:
        self.closed = True


class _FakeDestinationSocket:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.send_event = threading.Event()
        self.closed = False

    def sendall(self, chunk: bytes) -> None:
        self.sent.append(chunk)
        self.send_event.set()

    def close(self) -> None:
        self.closed = True


def test_relay_forwards_chunk_before_slow_packet_tracing_finishes(tmp_path, monkeypatch) -> None:
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
    )
    trace_started = threading.Event()
    trace_finished = threading.Event()

    def fake_extract_packets(frame_buf: bytearray) -> list[bytes]:
        if not frame_buf:
            return []
        data = bytes(frame_buf)
        frame_buf.clear()
        return [data]

    def slow_trace_packet(conn_id: str, direction: str, packet: bytes) -> None:
        assert conn_id == "1"
        assert direction == "c2b"
        assert packet == b"packet-bytes"
        trace_started.set()
        time.sleep(0.25)
        trace_finished.set()

    monkeypatch.setattr(proxy, "_extract_packets", fake_extract_packets)
    monkeypatch.setattr(proxy, "_trace_packet", slow_trace_packet)

    src = _FakeSourceSocket(b"packet-bytes")
    dst = _FakeDestinationSocket()
    proxy._running = True

    started_at = time.perf_counter()
    proxy._relay(src, dst, "1", "c2b", bytearray())
    elapsed = time.perf_counter() - started_at

    assert dst.sent == [b"packet-bytes"]
    assert dst.send_event.is_set()
    assert trace_started.wait(0.1)
    assert elapsed < 0.15
    assert trace_finished.wait(1.0)
    assert src.closed is True
    assert dst.closed is True

    proxy.stop()
