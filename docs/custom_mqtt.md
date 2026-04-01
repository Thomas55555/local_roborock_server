# Custom MQTT

Use this if you want the stack to connect to your own MQTT broker instead of the embedded Mosquitto instance described in [Installation](installation.md).

## Required Config

Set the broker section in `config.toml` like this before you start the stack:

```toml
[broker]
mode = "external"
host = "your-broker-hostname-or-ip"
port = 1883
enable_topic_bridge = true
```

The setup wizard will write `mode = "external"` for you if you choose an external broker, but you still need to fill in `broker.host` before starting.

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Docs index](index.md)
