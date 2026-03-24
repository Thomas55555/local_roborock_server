from pathlib import Path

from roborock_local_server.cloud import _to_jsonable


class _FakeSchema:
    def __init__(self, payload):
        self._payload = payload

    def as_dict(self):
        return self._payload


def test_to_jsonable_converts_nested_schema_objects() -> None:
    raw = {
        "root": _FakeSchema(
            {
                "child": _FakeSchema({"name": "vacuum"}),
                "items": [_FakeSchema({"id": 1}), Path("/tmp/test")],
            }
        )
    }

    converted = _to_jsonable(raw)

    assert converted == {
        "root": {
            "child": {"name": "vacuum"},
            "items": [{"id": 1}, str(Path("/tmp/test"))],
        }
    }
