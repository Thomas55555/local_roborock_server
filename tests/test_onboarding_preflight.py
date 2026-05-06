from __future__ import annotations

from io import StringIO

import pytest

import onboarding_shared


class _FakeApi:
    def __init__(self, status_payload: dict) -> None:
        self.status_payload = status_payload
        self.login_calls = 0
        self.status_calls = 0

    def login(self) -> None:
        self.login_calls += 1

    def get_status(self) -> dict:
        self.status_calls += 1
        return self.status_payload


def test_preflight_validates_api_services_and_mqtt_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int, bool, str]] = []

    def fake_probe(*, host: str, port: int, allow_insecure_tls: bool, label: str) -> None:
        calls.append((host, port, allow_insecure_tls, label))

    monkeypatch.setattr(onboarding_shared, "_probe_tls_endpoint", fake_probe)
    api = _FakeApi(
        {
            "health": {
                "services": [
                    {"name": "https_server", "running": True, "enabled": True, "detail": "tls:0.0.0.0:555"},
                    {"name": "mqtt_tls_proxy", "running": True, "enabled": True, "detail": "tls:0.0.0.0:1881"},
                    {"name": "mqtt_backend_broker", "running": True, "enabled": True, "detail": "embedded:127.0.0.1:18830"},
                ]
            }
        }
    )
    output = StringIO()

    onboarding_shared.perform_onboarding_preflight(
        api=api,
        api_base_url="https://api-roborock.example.com:555",
        allow_insecure_tls=False,
        output=output,
    )

    assert api.login_calls == 1
    assert api.status_calls == 1
    assert calls == [
        ("api-roborock.example.com", 555, False, "https://api-roborock.example.com:555"),
        ("api-roborock.example.com", 1881, False, "ssl://api-roborock.example.com:1881"),
    ]
    text = output.getvalue()
    assert "Admin API login succeeded." in text
    assert "Required services are running" in text
    assert "TLS certificate is valid and listener is reachable" in text


def test_preflight_rejects_missing_or_stopped_required_service() -> None:
    api = _FakeApi(
        {
            "health": {
                "services": [
                    {"name": "https_server", "running": True, "enabled": True, "detail": "tls:0.0.0.0:555"},
                    {"name": "mqtt_tls_proxy", "running": False, "enabled": True, "detail": "tls:0.0.0.0:8881"},
                    {"name": "mqtt_backend_broker", "running": True, "enabled": True, "detail": "embedded:127.0.0.1:18830"},
                ]
            }
        }
    )

    with pytest.raises(RuntimeError, match="mqtt_tls_proxy is not running"):
        onboarding_shared.perform_onboarding_preflight(
            api=api,
            api_base_url="https://api-roborock.example.com:555",
            allow_insecure_tls=False,
            output=StringIO(),
        )


def test_preflight_reports_when_tls_verification_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onboarding_shared, "_probe_tls_endpoint", lambda **kwargs: None)
    api = _FakeApi(
        {
            "health": {
                "services": [
                    {"name": "https_server", "running": True, "enabled": True, "detail": "tls:0.0.0.0:555"},
                    {"name": "mqtt_tls_proxy", "running": True, "enabled": True, "detail": "tls:0.0.0.0:8881"},
                    {"name": "mqtt_backend_broker", "running": True, "enabled": True, "detail": "embedded:127.0.0.1:18830"},
                ]
            }
        }
    )
    output = StringIO()

    onboarding_shared.perform_onboarding_preflight(
        api=api,
        api_base_url="https://api-roborock.example.com:555",
        allow_insecure_tls=True,
        output=output,
    )

    assert "certificate verification skipped" in output.getvalue()
