import json

from roborock_local_server.backend import _build_inventory


class _FakeSchemaValue:
    def __init__(self, payload):
        self._payload = payload

    def as_dict(self):
        return self._payload


class _FakeCategory:
    value = "vacuum"


class _FakeProduct:
    def __init__(self):
        self.id = "product-1"
        self.name = "Qrevo"
        self.model = "roborock.qrevo"
        self.category = _FakeCategory()
        self.capability = _FakeSchemaValue({"map_carpet_add_supported": True})
        self.schema = [_FakeSchemaValue({"id": "fan_power", "type": "enum"})]


class _FakeDevice:
    def __init__(self):
        self.duid = "device-1"
        self.name = "Living Room Vacuum"
        self.local_key = "secret"
        self.product_id = "product-1"
        self.pv = "1.0"
        self.fv = "2.0"
        self.time_zone_id = "America/New_York"
        self.room_id = 12
        self.online = True
        self.sn = "RR123"


class _FakeHomeData:
    def __init__(self):
        self.id = 123
        self.name = "Home"
        self.rooms = []
        self.devices = [_FakeDevice()]
        self.received_devices = []
        self.products = [_FakeProduct()]
        self.lon = None
        self.lat = None
        self.geo_name = None


def test_build_inventory_normalizes_product_schema_objects() -> None:
    inventory = _build_inventory(_FakeHomeData())

    assert inventory["devices"][0]["capability"] == {"map_carpet_add_supported": True}
    assert inventory["devices"][0]["schema"] == [{"id": "fan_power", "type": "enum"}]
    json.dumps(inventory)
